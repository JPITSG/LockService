export interface Settings {
  bindIP: string;
  bindPort: number;
  enableHTTP: boolean;
  enableMonitorOff: boolean;
}

export interface ServiceState {
  state: number; // 0=not installed, 1=stopped, 2=running, 3=transitioning
  label: string;
}

export interface ActionResult {
  action: string;
  success: boolean;
}

type SettingsCallback = (settings: Settings) => void;
type ServiceStateCallback = (state: ServiceState) => void;
type ActionResultCallback = (result: ActionResult) => void;

let settingsCallback: SettingsCallback | null = null;
let serviceStateCallback: ServiceStateCallback | null = null;
let actionResultCallback: ActionResultCallback | null = null;

// Extend window for C ↔ JS bridge
declare global {
  interface Window {
    onSettingsUpdate: (settings: Settings) => void;
    onServiceStateUpdate: (state: ServiceState) => void;
    onActionResult: (result: ActionResult) => void;
    chrome?: {
      webview?: {
        postMessage: (s: string) => void;
      };
    };
  }
}

// Called by C via ExecuteScript
window.onSettingsUpdate = (settings: Settings) => {
  settingsCallback?.(settings);
};

window.onServiceStateUpdate = (state: ServiceState) => {
  serviceStateCallback?.(state);
};

window.onActionResult = (result: ActionResult) => {
  actionResultCallback?.(result);
};

export function onSettings(cb: SettingsCallback) {
  settingsCallback = cb;
}

export function onServiceState(cb: ServiceStateCallback) {
  serviceStateCallback = cb;
}

export function onActionResult(cb: ActionResultCallback) {
  actionResultCallback = cb;
}

function postMessage(msg: Record<string, unknown>) {
  try {
    window.chrome?.webview?.postMessage(JSON.stringify(msg));
  } catch {
    console.log("postMessage (no WebView2):", msg);
  }
}

export function reportHeight(height: number) {
  postMessage({ action: "resize", height });
}

export function getSettings() {
  postMessage({ action: "getSettings" });
}

export function saveSettings(settings: Settings) {
  postMessage({
    action: "saveSettings",
    bindIP: settings.bindIP,
    bindPort: settings.bindPort,
    enableHTTP: settings.enableHTTP,
    enableMonitorOff: settings.enableMonitorOff,
  });
}

export function getServiceState() {
  postMessage({ action: "getServiceState" });
}

export function installService() {
  postMessage({ action: "install" });
}

export function uninstallService() {
  postMessage({ action: "uninstall" });
}

export function startService() {
  postMessage({ action: "start" });
}

export function stopService() {
  postMessage({ action: "stop" });
}

export function restartService() {
  postMessage({ action: "restart" });
}
