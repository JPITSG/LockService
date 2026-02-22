import { useEffect, useRef, useState, useCallback } from "react";
import { Button } from "./components/ui/button";
import { Input } from "./components/ui/input";
import { Switch } from "./components/ui/switch";
import { Separator } from "./components/ui/separator";
import { Badge } from "./components/ui/badge";
import { Label } from "./components/ui/label";
import {
  onSettings,
  onServiceState,
  onActionResult,
  getSettings,
  getServiceState,
  saveSettings,
  reportHeight,
  installService,
  uninstallService,
  startService,
  stopService,
  restartService,
  type Settings,
  type ServiceState,
} from "./lib/bridge";

function stateLabel(state: number): string {
  switch (state) {
    case 0:
      return "Not Installed";
    case 1:
      return "Stopped";
    case 2:
      return "Running";
    case 3:
      return "Transitioning...";
    default:
      return "Unknown";
  }
}

function stateBadgeVariant(
  state: number
): "success" | "destructive" | "secondary" | "outline" {
  switch (state) {
    case 2:
      return "success";
    case 1:
      return "destructive";
    case 0:
      return "outline";
    default:
      return "secondary";
  }
}

export default function App() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [serviceState, setServiceState] = useState<number>(-1);
  const [bindIP, setBindIP] = useState("0.0.0.0");
  const [bindPort, setBindPort] = useState("8888");
  const [enableHTTP, setEnableHTTP] = useState(true);
  const [enableMonitorOff, setEnableMonitorOff] = useState(true);
  const [origSettings, setOrigSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);

  const isDirty =
    origSettings !== null &&
    (bindIP !== origSettings.bindIP ||
      bindPort !== String(origSettings.bindPort) ||
      enableHTTP !== origSettings.enableHTTP ||
      enableMonitorOff !== origSettings.enableMonitorOff);

  const applySettings = useCallback((s: Settings) => {
    setBindIP(s.bindIP);
    setBindPort(String(s.bindPort));
    setEnableHTTP(s.enableHTTP);
    setEnableMonitorOff(s.enableMonitorOff);
    setOrigSettings(s);
  }, []);

  useEffect(() => {
    onSettings((s) => applySettings(s));
    onServiceState((st: ServiceState) => {
      setServiceState(st.state);
      setBusy(false);
    });
    onActionResult(() => {
      getServiceState();
      getSettings();
    });

    getSettings();
    getServiceState();
  }, [applySettings]);

  // Equalize setting row heights then report content height to C
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const equalizeAndReport = () => {
      const rows = el.querySelectorAll<HTMLElement>("[data-row]");
      // Reset to auto so we measure natural heights
      rows.forEach((r) => (r.style.minHeight = ""));
      const maxH = Array.from(rows).reduce(
        (max, r) => Math.max(max, r.offsetHeight),
        0
      );
      if (maxH > 0) {
        rows.forEach((r) => (r.style.minHeight = `${maxH}px`));
      }
      reportHeight(Math.ceil(el.scrollHeight));
    };

    const rafId = requestAnimationFrame(equalizeAndReport);
    const observer = new ResizeObserver(equalizeAndReport);
    observer.observe(el);
    return () => {
      cancelAnimationFrame(rafId);
      observer.disconnect();
    };
  }, []);

  const handleSave = () => {
    const port = parseInt(bindPort, 10);
    if (isNaN(port) || port < 1 || port > 65535) return;
    setBusy(true);
    saveSettings({ bindIP, bindPort: port, enableHTTP, enableMonitorOff });
  };

  const handleAction = (action: () => void) => {
    setBusy(true);
    action();
  };

  const installed = serviceState > 0;
  const running = serviceState === 2;
  const stopped = serviceState === 1;

  return (
    <div ref={containerRef} className="p-5 flex flex-col gap-4 max-w-md mx-auto">
      {/* Settings */}
      <div className="flex flex-col gap-3">
        {/* Status badge — right-aligned above switches */}
        <div data-row className="flex items-center justify-between">
          <Label>Service Status</Label>
          {serviceState >= 0 ? (
            <Badge variant={stateBadgeVariant(serviceState)}>
              {stateLabel(serviceState)}
            </Badge>
          ) : (
            <Badge variant="secondary">Checking...</Badge>
          )}
        </div>

        <div data-row className="flex items-center justify-between">
          <Label htmlFor="enable-http">Enable HTTP Service</Label>
          <Switch
            id="enable-http"
            checked={enableHTTP}
            onCheckedChange={setEnableHTTP}
          />
        </div>

        <div data-row className="flex items-center justify-between">
          <Label htmlFor="enable-monoff">Turn off monitor(s) on WIN+L</Label>
          <Switch
            id="enable-monoff"
            checked={enableMonitorOff}
            onCheckedChange={setEnableMonitorOff}
          />
        </div>

        <div data-row className="flex items-center justify-between">
          <Label htmlFor="bind-ip">Bind IP</Label>
          <Input
            id="bind-ip"
            value={bindIP}
            onChange={(e) => setBindIP(e.target.value)}
            placeholder="0.0.0.0"
            className="w-36"
          />
        </div>

        <div data-row className="flex items-center justify-between">
          <Label htmlFor="bind-port">Bind Port</Label>
          <Input
            id="bind-port"
            type="number"
            min={1}
            max={65535}
            value={bindPort}
            onChange={(e) => setBindPort(e.target.value)}
            placeholder="8888"
            className="w-36"
          />
        </div>

        <div className="flex justify-end">
          <Button size="sm" disabled={!isDirty || busy} onClick={handleSave}>
            Save
          </Button>
        </div>
      </div>

      <Separator />

      {/* Service actions */}
      <div className="grid grid-cols-5 gap-2">
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          disabled={installed || busy}
          onClick={() => handleAction(installService)}
        >
          Install
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          disabled={!installed || busy}
          onClick={() => handleAction(uninstallService)}
        >
          Uninstall
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          disabled={!running || busy}
          onClick={() => handleAction(restartService)}
        >
          Restart
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          disabled={!stopped || busy}
          onClick={() => handleAction(startService)}
        >
          Start
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="w-full"
          disabled={!running || busy}
          onClick={() => handleAction(stopService)}
        >
          Stop
        </Button>
      </div>
    </div>
  );
}
