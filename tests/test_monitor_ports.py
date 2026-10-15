"""Exercise the port monitor without starting the daemon or touching the host."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).parents[1] / "scripts" / "sentinel_daemon.py"


class StopMonitor(BaseException):
    pass


class PortMonitorTests(unittest.TestCase):
    def test_monitor_detects_external_port_and_ignores_loopback(self):
        tree = ast.parse(SOURCE.read_text())  # Regression: indentation prevented startup.
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "monitor_ports")
        calls = 0
        alerts = []
        def connections(kind):
            nonlocal calls
            calls += 1
            ports = [("127.0.0.1", 5000), ("::1", 5001), ("0.0.0.0", 22)]
            if calls > 1:
                ports.append(("0.0.0.0", 4444))
            return [SimpleNamespace(status="LISTEN", laddr=SimpleNamespace(ip=ip, port=port)) for ip, port in ports]
        def sleep(_):
            if calls >= 2:
                raise StopMonitor()
        scope = {
            "psutil": SimpleNamespace(net_connections=connections),
            "time": SimpleNamespace(sleep=sleep), "POLL_PORTS": 0,
            "state": {"known_ports": set(), "alerted_ports": set()},
            "should_alert": lambda _: True,
            "send_alert": lambda message, level: alerts.append((message, level)),
            "log": SimpleNamespace(warning=lambda *a: None, error=lambda *a: None),
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), scope)
        with self.assertRaises(StopMonitor):
            scope["monitor_ports"]()
        self.assertEqual(scope["state"]["known_ports"], {22, 4444})
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][1], "high")
        self.assertIn("4444", alerts[0][0])


if __name__ == "__main__":
    unittest.main()
