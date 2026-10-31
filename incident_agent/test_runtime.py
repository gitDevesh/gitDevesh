import asyncio
import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

import main


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_planning_does_not_block_health_or_other_requests(self):
        with tempfile.TemporaryDirectory(prefix="incident-concurrency-") as folder:
            with patch.object(main,"DB_PATH",os.path.join(folder,"runs.sqlite3")):
                main.init_db()
                plan={"rootCause":"capacity", "evidence":["ev1","ev2"], "diagnostics":[{"toolName":"query_metrics","arguments":{},"evidence":["ev1"]}], "effect":{"toolName":"page_owner","arguments":{},"evidence":["ev2"]}}
                body={"profile":main.PROFILE,"runId":"concurrency-"+uuid.uuid4().hex,"agentName":"incident-response","publicMarker":"public-marker","incident":{"incidentId":"test","transcript":"[ev1] Capacity limit reached\n[ev2] Owner team acknowledged","allowedRootCauses":["capacity"]},"toolCatalog":[{"name":"query_metrics","inputSchema":{"type":"object"}},{"name":"page_owner","inputSchema":{"type":"object"}}],"policy":{"maximumDiagnostics":1,"effectTools":["page_owner"],"approvalRequiredFor":[]}}
                def slow_plan(*args):
                    time.sleep(0.25)
                    return plan
                async with AsyncClient(transport=ASGITransport(app=main.app),base_url="http://test") as client:
                    with patch("main.call_planner",side_effect=slow_plan):
                        pending=asyncio.create_task(client.post("/v2/incidents",json=body))
                        await asyncio.sleep(0.04)
                        health=await asyncio.wait_for(client.get("/health"),timeout=0.1)
                        self.assertEqual(health.status_code,200)
                        self.assertFalse(pending.done())
                        self.assertEqual((await pending).status_code,200)


if __name__=="__main__":
    unittest.main()
