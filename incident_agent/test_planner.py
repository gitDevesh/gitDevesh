import copy
import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

import planner


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.incident={"incidentId":"INC-TEST", "service":"checkout", "severity":"SEV-2", "transcript":"[ev_release] Release release-17 caused errors.\n[ev_owner] Team Checkout owns the service.", "allowedRootCauses":["bad_release","capacity"]}
        self.catalog=[{"name":"inspect_deployment","inputSchema":{"type":"object","properties":{"service":{"type":"string"},"releaseId":{"type":"string"}},"required":["service","releaseId"],"additionalProperties":False}}, {"name":"page_owner","inputSchema":{"type":"object","properties":{"team":{"type":"string"}},"required":["team"]}}]
        self.policy={"maximumDiagnostics":2,"effectTools":["page_owner"],"approvalRequiredFor":[]}
        self.args={"rootCause":"bad_release","evidence":["ev_release","ev_owner"],"diagnostics":[{"toolName":"inspect_deployment","argumentsJson":json.dumps({"service":"checkout","releaseId":"release-17"}),"evidence":["ev_release"]}],"effect":{"toolName":"page_owner","argumentsJson":json.dumps({"team":"Checkout"}),"evidence":["ev_owner"]}}

    def payload(self,args=None):
        return {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":planner.PLAN_FUNCTION,"args":args or self.args}}]}}]}

    def test_single_provider_call_returns_complete_plan_and_preserves_large_input(self):
        self.incident["transcript"] += "\n"+"\n".join(f"[noise_{i}] Unrelated healthy background job completed normally." for i in range(1600))
        response=io.BytesIO(json.dumps(self.payload()).encode())
        with patch.dict(os.environ,{"GEMINI_API_KEY":"not-a-real-key"}),patch("planner.urllib.request.urlopen",return_value=response) as send:
            plan=planner.call_planner("incident-response",self.incident,self.catalog,self.policy,self.incident["allowedRootCauses"],["ev_release","ev_owner"])
        self.assertEqual(send.call_count,1)
        request=json.loads(send.call_args.args[0].data)
        self.assertEqual(len(request["tools"][0]["functionDeclarations"]),1)
        self.assertEqual(request["tools"][0]["functionDeclarations"][0]["name"],planner.PLAN_FUNCTION)
        self.assertIn("[noise_1599]",request["contents"][0]["parts"][0]["text"])
        self.assertNotIn("not-a-real-key",json.dumps(request))
        self.assertNotIn("oneOf",json.dumps(request["tools"]))
        self.assertEqual(plan["diagnostics"][0]["arguments"],{"service":"checkout","releaseId":"release-17"})
        self.assertEqual(plan["effect"]["arguments"],{"team":"Checkout"})

    def test_argument_json_keeps_nested_types(self):
        args=copy.deepcopy(self.args)
        nested={"replicas":4,"enabled":False,"labels":{"region":"eu-west"},"ports":[80,443]}
        args["effect"]["argumentsJson"]=json.dumps(nested)
        self.assertEqual(planner.decode_plan(self.payload(args))["effect"]["arguments"],nested)

    def test_malformed_argument_json_is_rejected_without_guessing(self):
        for value in ('{"service":"checkout","service":"other"}', '[]', '{broken'):
            args=copy.deepcopy(self.args);args["effect"]["argumentsJson"]=value
            with self.subTest(value=value),self.assertRaises(RuntimeError):
                planner.decode_plan(self.payload(args))

    def test_partial_or_multiple_function_calls_fail_safely(self):
        args=copy.deepcopy(self.args);del args["effect"]
        with self.assertRaises(RuntimeError):planner.decode_plan(self.payload(args))
        payload=self.payload();payload["candidates"][0]["content"]["parts"]*=2
        with self.assertRaises(RuntimeError):planner.decode_plan(payload)

    def test_only_transient_provider_503_is_retried(self):
        failure=urllib.error.HTTPError("https://provider.invalid",503,"unavailable",{},io.BytesIO(b'{"secret":"never-log-this"}'))
        success=io.BytesIO(json.dumps(self.payload()).encode())
        with patch.dict(os.environ,{"GEMINI_API_KEY":"not-a-real-key"}),patch("planner.urllib.request.urlopen",side_effect=[failure,success]) as send:
            planner.call_planner("incident-response",self.incident,self.catalog,self.policy,self.incident["allowedRootCauses"],["ev_release","ev_owner"])
        self.assertEqual(send.call_count,2)
        failure=urllib.error.HTTPError("https://provider.invalid",400,"bad request",{},io.BytesIO(b"sensitive provider error"))
        with patch.dict(os.environ,{"GEMINI_API_KEY":"not-a-real-key"}),patch("planner.urllib.request.urlopen",side_effect=failure) as send:
            with self.assertRaisesRegex(RuntimeError,"HTTP 400"):
                planner.call_planner("incident-response",self.incident,self.catalog,self.policy,self.incident["allowedRootCauses"],["ev_release","ev_owner"])
        self.assertEqual(send.call_count,1)


if __name__ == "__main__":
    unittest.main()
