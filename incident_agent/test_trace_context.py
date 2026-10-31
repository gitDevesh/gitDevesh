import unittest

from starlette.requests import Request

import telemetry


class TraceContextTests(unittest.TestCase):
    def context(self, headers):
        return telemetry.trace_context(Request({"type":"http", "headers":[(k.encode(), v.encode()) for k,v in headers]}))

    def test_multitenant_tracestate_and_multiple_headers_are_preserved(self):
        parent = "00-"+"a"*32+"-"+"b"*16+"-00"
        value = self.context([("traceparent",parent), ("tracestate","42tenant@vendor=opaque"), ("tracestate","other=second")])
        self.assertEqual(value["traceId"], "a"*32)
        self.assertEqual(value["traceFlagsHex"], "00")
        self.assertEqual(value["tracestate"], "42tenant@vendor=opaque,other=second")

    def test_reserved_flags_are_not_mistaken_for_invalid_version(self):
        value = self.context([("traceparent","00-"+"a"*32+"-"+"b"*16+"-ff")])
        self.assertEqual(value["traceId"], "a"*32)
        self.assertEqual(value["traceFlagsHex"], "01")

    def test_future_traceparent_version_continues_known_context(self):
        value = self.context([("traceparent","01-"+"a"*32+"-"+"b"*16+"-03-future-data")])
        self.assertEqual(value["traceId"], "a"*32)
        self.assertEqual(value["traceFlagsHex"], "01")

    def test_invalid_parent_restarts_trace_and_drops_tracestate(self):
        examples = [
            "ff-"+"a"*32+"-"+"b"*16+"-01",
            "00-"+"0"*32+"-"+"b"*16+"-01",
            "00-"+"a"*32+"-"+"0"*16+"-01",
            "00-"+"A"*32+"-"+"b"*16+"-01",
            "00-"+"a"*32+"-"+"b"*16+"-01-extra",
        ]
        for parent in examples:
            with self.subTest(parent=parent):
                value = self.context([("traceparent",parent), ("tracestate","vendor=opaque")])
                self.assertNotEqual(value["traceId"], "a"*32)
                self.assertNotEqual(int(value["traceId"],16), 0)
                self.assertEqual(value["upstreamParentSpanId"], "")
                self.assertIsNone(value["tracestate"])

    def test_duplicate_traceparent_is_invalid(self):
        parent="00-"+"a"*32+"-"+"b"*16+"-01"
        value=self.context([("traceparent",parent),("traceparent",parent)])
        self.assertNotEqual(value["traceId"], "a"*32)

    def test_tracestate_grammar_and_empty_members(self):
        for value in ("vendor=value", "a@vendor=value", "1tenant@vendor=value", "vendor=value, ,other=next", ""):
            self.assertEqual(telemetry.valid_tracestate(value), value)
        for value in ("1vendor=value", "vendor=a=b", "vendor=a,vendor=b", "vendor=", "VENDOR=value", "vendor=a\tb", "tenant@1vendor=value"):
            self.assertIsNone(telemetry.valid_tracestate(value))
        self.assertIsNone(telemetry.valid_tracestate(",".join(f"v{i}=x" for i in range(33))))

    def test_invalid_tracestate_does_not_invalidate_traceparent(self):
        value=self.context([("traceparent","00-"+"a"*32+"-"+"b"*16+"-01"),("tracestate","vendor=invalid=value")])
        self.assertEqual(value["traceId"], "a"*32)
        self.assertIsNone(value["tracestate"])


if __name__ == "__main__":
    unittest.main()
