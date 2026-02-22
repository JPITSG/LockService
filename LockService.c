// lockservice_nowindow.c
// Compile with: x86_64-w64-mingw32-gcc -O2 -Wall -o LockService.exe lockservice_nowindow.c -lws2_32 -ladvapi32 -lwtsapi32 -luserenv -s

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <initguid.h>
#include <objbase.h>

#define SERVICE_NAME "LockService"
#define SERVICE_DISPLAY_NAME_W L"Lock Screen Service"
#define HTTP_PORT 8888
#define HELP_FLAG "--helper"
#define KEYBOARD_HOOK_FLAG "--keyboard-hook"

// Timeout constants (in milliseconds)
#define SESSION_POLL_INTERVAL_MS 10000
#define THREAD_SHUTDOWN_TIMEOUT_MS 5000
#define HTTP_SELECT_TIMEOUT_MS 100

// Virtual key code for 'L' key
#define VK_KEY_L 0x4C

// Resource IDs
#define IDI_APP_ICON 100
#define IDR_HTML_UI 200
#define IDR_WEBVIEW2_DLL 201

// Registry settings
#define REG_KEY_PATH       "SOFTWARE\\JPIT\\LockService"
#define REG_VALUE_BIND_IP  "BindIP"
#define REG_VALUE_BIND_PORT "BindPort"
#define REG_VALUE_ENABLE_HTTP   "EnableHTTP"
#define REG_VALUE_ENABLE_MONOFF "EnableMonitorOff"

// Settings globals
static char g_bindIP[64] = "0.0.0.0";
static DWORD g_bindPort = 8888;
static DWORD g_enableHTTP = 1;
static DWORD g_enableMonitorOff = 1;

// Forward declaration
static void load_settings(void);

// Global service status handle
static SERVICE_STATUS g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle;
static HANDLE g_ServiceStopEvent = NULL;

// Keyboard hook globals
static HHOOK g_hKeyboardHook = NULL;
static BOOL g_bWinKeyPressed = FALSE;

// Session monitoring globals
#define MAX_TRACKED_SESSIONS 32

typedef struct {
	DWORD sessionId;
	HANDLE hProcess;
} HELPER_PROC;

#define HELPER_HANDLE_LAUNCHING ((HANDLE)(LONG_PTR)-1)

static HELPER_PROC g_HelperProcs[MAX_TRACKED_SESSIONS];
static DWORD g_HelperProcCount = 0;
static CRITICAL_SECTION g_SessionLock;

// Single-instance mutex for keyboard hook helper
static HANDLE g_hSingleInstanceMutex = NULL;

static BOOL ensure_single_keyboard_helper_instance(void) {
	DWORD sid = 0;
	char name[128];

	if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid))
		sid = 0;

	snprintf(name, sizeof(name), "Local\\LockServiceKbHelper-%lu", sid);

	g_hSingleInstanceMutex = CreateMutexA(NULL, TRUE, name);
	if (!g_hSingleInstanceMutex)
		return TRUE;

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(g_hSingleInstanceMutex);
		g_hSingleInstanceMutex = NULL;
		return FALSE;
	}

	return TRUE;
}

// Event logging
static HANDLE g_hEventLog = NULL;

// Log to Windows Event Viewer
static void log_event(WORD type, const char* message) {
    if (!g_hEventLog) return;
    
    const char* strings[1] = { message };
    ReportEventA(g_hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
}

// Log error with formatted message
static void log_error(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    log_event(EVENTLOG_ERROR_TYPE, buffer);
    fprintf(stderr, "ERROR: %s\n", buffer);
}

// Log info message
static void log_info(const char* format, ...) {
    char buffer[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    log_event(EVENTLOG_INFORMATION_TYPE, buffer);
    printf("INFO: %s\n", buffer);
}

// Window procedure for RawInput processing
static LRESULT CALLBACK raw_input_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_INPUT) {
        RAWINPUT raw;
        UINT size = sizeof(raw);
        
        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, &raw, &size, sizeof(RAWINPUTHEADER)) != (UINT)-1) {
            if (raw.header.dwType == RIM_TYPEKEYBOARD) {
                USHORT vkey = raw.data.keyboard.VKey;
                USHORT flags = raw.data.keyboard.Flags;
                BOOL isKeyDown = !(flags & RI_KEY_BREAK);
                
                // Track Win key state
                if (vkey == VK_LWIN || vkey == VK_RWIN) {
                    g_bWinKeyPressed = isKeyDown;
                }
                
                // Detect L key press
                if (vkey == VK_KEY_L && isKeyDown && g_bWinKeyPressed) {
                    // Double-check Win key is pressed
                    SHORT winLeftState = GetAsyncKeyState(VK_LWIN);
                    SHORT winRightState = GetAsyncKeyState(VK_RWIN);
                    BOOL winCurrentlyPressed = (winLeftState & 0x8000) || (winRightState & 0x8000);
                    
                    if (winCurrentlyPressed) {
                        // Check no other modifiers
                        SHORT ctrlState = GetAsyncKeyState(VK_CONTROL);
                        SHORT altState = GetAsyncKeyState(VK_MENU);
                        SHORT shiftState = GetAsyncKeyState(VK_SHIFT);
                        
                        if (!(ctrlState & 0x8000) && !(altState & 0x8000) && !(shiftState & 0x8000)) {
                            char username[256] = {0};
                            DWORD usernameLen = sizeof(username);
                            if (GetUserNameA(username, &usernameLen)) {
                                log_info("Detected WIN+L press from %s", username);
                            } else {
                                log_info("Detected WIN+L press");
                            }
                            if (g_enableMonitorOff) {
                                Sleep(500);
                                SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
                            }
                        }
                    }
                }
            }
        }
    } else if (msg == WM_HOTKEY && wParam == 1) {
        // Hotkey backup
        char username[256] = {0};
        DWORD usernameLen = sizeof(username);
        if (GetUserNameA(username, &usernameLen)) {
            log_info("Detected WIN+L press from %s", username);
        } else {
            log_info("Detected WIN+L press");
        }
        if (g_enableMonitorOff) {
            Sleep(500);
            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
        }
    }
    
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// Keyboard hook callback (kept as secondary backup)
static LRESULT CALLBACK keyboard_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKbd = (KBDLLHOOKSTRUCT*)lParam;
        BOOL isKeyDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        BOOL isKeyUp = (wParam == WM_KEYUP || wParam == WM_SYSKEYUP);
        
        // Track Win key state
        if (pKbd->vkCode == VK_LWIN || pKbd->vkCode == VK_RWIN) {
            if (isKeyDown) {
                g_bWinKeyPressed = TRUE;
            } else if (isKeyUp) {
                g_bWinKeyPressed = FALSE;
            }
        }
        
        // Detect L key press (VK_KEY_L)
        if (pKbd->vkCode == VK_KEY_L && isKeyDown) {
            // First verify Win key is CURRENTLY pressed using GetAsyncKeyState
            SHORT winLeftState = GetAsyncKeyState(VK_LWIN);
            SHORT winRightState = GetAsyncKeyState(VK_RWIN);
            BOOL winCurrentlyPressed = (winLeftState & 0x8000) || (winRightState & 0x8000);
            
            // Only proceed if Win key is actually pressed right now AND our flag agrees
            if (g_bWinKeyPressed && winCurrentlyPressed) {
                // Check that ONLY Win key is pressed (no other modifiers)
                SHORT ctrlState = GetAsyncKeyState(VK_CONTROL);
                SHORT altState = GetAsyncKeyState(VK_MENU);
                SHORT shiftState = GetAsyncKeyState(VK_SHIFT);
                
                // Only trigger if no other modifiers are pressed
                if (!(ctrlState & 0x8000) && !(altState & 0x8000) && !(shiftState & 0x8000)) {
                    // Win+L detected! Get username and log it
                    char username[256] = {0};
                    DWORD usernameLen = sizeof(username);
                    if (GetUserNameA(username, &usernameLen)) {
                        log_info("Detected WIN+L press from %s", username);
                    } else {
                        log_info("Detected WIN+L press");
                    }
                    
                    // Turn off monitors using SendMessage for reliability
                    if (g_enableMonitorOff) {
                        Sleep(500);
                        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
                    }
                }
            }
        }
    }
    
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

// Keyboard hook helper process entry point
static void run_keyboard_hook_helper(void) {
	if (!ensure_single_keyboard_helper_instance())
		exit(0);

    load_settings();

    MSG msg;
    HWND hwnd = NULL;
    
    // Open event log for this helper process
    g_hEventLog = RegisterEventSourceA(NULL, SERVICE_NAME);
    
    // Create a hidden window with custom window procedure for RawInput
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = raw_input_wnd_proc;
    wc.lpszClassName = "LockServiceHotkeyWindow";
    wc.hInstance = GetModuleHandle(NULL);
    
    if (!RegisterClassA(&wc)) {
        DWORD dwError = GetLastError();
        // If class already exists (from crashed helper), that's okay - reuse it
        if (dwError != ERROR_CLASS_ALREADY_EXISTS) {
            if (g_hEventLog) {
                log_error("RegisterClass failed: %lu", dwError);
                DeregisterEventSource(g_hEventLog);
            }
            exit(1);
        }
    }
    
    hwnd = CreateWindowA(wc.lpszClassName, "", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    if (!hwnd) {
        if (g_hEventLog) {
            log_error("CreateWindow failed: %lu", GetLastError());
            DeregisterEventSource(g_hEventLog);
        }
        exit(1);
    }
    
    // Register for raw keyboard input (works with elevated apps)
    RAWINPUTDEVICE rid = {0};
    rid.usUsagePage = 0x01;  // HID_USAGE_PAGE_GENERIC
    rid.usUsage = 0x06;      // HID_USAGE_GENERIC_KEYBOARD
    rid.dwFlags = RIDEV_INPUTSINK;  // Receive input even when not in foreground
    rid.hwndTarget = hwnd;
    
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        if (g_hEventLog) {
            log_error("RegisterRawInputDevices failed: %lu", GetLastError());
            DeregisterEventSource(g_hEventLog);
        }
        DestroyWindow(hwnd);
        exit(1);
    }
    
    // Register Win+L as a hotkey (backup mechanism)
    RegisterHotKey(hwnd, 1, MOD_WIN, VK_KEY_L);
    
    // Install low-level keyboard hook (tertiary backup for non-elevated contexts)
    g_hKeyboardHook = SetWindowsHookExA(WH_KEYBOARD_LL, keyboard_hook_proc, GetModuleHandle(NULL), 0);
    
    // Message loop to handle RawInput, hotkeys, and hooks
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Cleanup
    if (g_hKeyboardHook) UnhookWindowsHookEx(g_hKeyboardHook);
    UnregisterHotKey(hwnd, 1);
    
    // Unregister RawInput
    rid.dwFlags = RIDEV_REMOVE;
    rid.hwndTarget = NULL;
    RegisterRawInputDevices(&rid, 1, sizeof(rid));
    
    DestroyWindow(hwnd);
    UnregisterClassA(wc.lpszClassName, wc.hInstance);

	if (g_hSingleInstanceMutex) {
		ReleaseMutex(g_hSingleInstanceMutex);
		CloseHandle(g_hSingleInstanceMutex);
		g_hSingleInstanceMutex = NULL;
	}
    
    if (g_hEventLog) {
        DeregisterEventSource(g_hEventLog);
    }
    exit(0);
}

// Helper process entry point
static void run_helper(void) {
    g_hEventLog = RegisterEventSourceA(NULL, SERVICE_NAME);
    load_settings();
    
    if (!LockWorkStation()) {
        if (g_hEventLog) {
            log_error("LockWorkStation failed: %lu", GetLastError());
            DeregisterEventSource(g_hEventLog);
        }
        exit(1);
    }
    if (g_enableMonitorOff) {
        Sleep(500);
        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
    }
    
    if (g_hEventLog) {
        DeregisterEventSource(g_hEventLog);
    }
    exit(0);
}

// Launch helper process in specified session
static BOOL launch_helper_in_session(DWORD sessionId) {
    HANDLE hToken = NULL, hDupToken = NULL;
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    LPVOID pEnvironment = NULL;
    WCHAR szExePath[MAX_PATH];
    WCHAR szCmdLine[MAX_PATH + 64];  // Increased buffer size
    BOOL bResult = FALSE;
    DWORD dwError;
    
    if (!GetModuleFileNameW(NULL, szExePath, MAX_PATH)) {
        dwError = GetLastError();
        log_error("GetModuleFileName failed: %lu", dwError);
        return FALSE;
    }
    
    swprintf(szCmdLine, sizeof(szCmdLine)/sizeof(WCHAR), L"\"%s\" %S", szExePath, HELP_FLAG);
    
    // FIX: Hide the window completely
    si.cb = sizeof(si);
    si.lpDesktop = L"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW;  // Use wShowWindow field
    si.wShowWindow = SW_HIDE;           // Hide the window
    
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        dwError = GetLastError();
        log_error("WTSQueryUserToken failed for session %lu: %lu", sessionId, dwError);
        return FALSE;
    }
    
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hDupToken)) {
        dwError = GetLastError();
        log_error("DuplicateTokenEx failed: %lu", dwError);
        goto cleanup;
    }
    
    if (!CreateEnvironmentBlock(&pEnvironment, hDupToken, FALSE)) {
        dwError = GetLastError();
        log_error("CreateEnvironmentBlock failed: %lu", dwError);
        goto cleanup;
    }
    
    // FIX: Use CREATE_NO_WINDOW instead of CREATE_NEW_CONSOLE
    bResult = CreateProcessAsUserW(
        hDupToken, NULL, szCmdLine, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,  // No console window
        pEnvironment, NULL, &si, &pi
    );
    
    if (bResult) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        dwError = GetLastError();
        log_error("CreateProcessAsUserW failed: %lu", dwError);
    }
    
cleanup:
    if (pEnvironment) DestroyEnvironmentBlock(pEnvironment);
    if (hDupToken) CloseHandle(hDupToken);
    if (hToken) CloseHandle(hToken);
    return bResult;
}

// Enumerate active sessions and lock them all
static void lock_all_sessions(void) {
    PWTS_SESSION_INFOW pSessions = NULL;
    DWORD sessionCount = 0;
    DWORD dwError;
    
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &sessionCount)) {
        dwError = GetLastError();
        log_error("WTSEnumerateSessions failed: %lu", dwError);
        return;
    }
    
    for (DWORD i = 0; i < sessionCount; i++) {
        if (pSessions[i].State == WTSActive) {
            launch_helper_in_session(pSessions[i].SessionId);
        }
    }
    
    WTSFreeMemory(pSessions);
}

// Launch keyboard hook helper in specified session
static BOOL launch_keyboard_hook_in_session(DWORD sessionId, HANDLE *outProcess) {
    HANDLE hToken = NULL, hDupToken = NULL;
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    LPVOID pEnvironment = NULL;
    WCHAR szExePath[MAX_PATH];
    WCHAR szCmdLine[MAX_PATH + 64];  // Increased buffer size
    BOOL bResult = FALSE;
    DWORD dwError;
    
	if (outProcess)
		*outProcess = NULL;

    if (!GetModuleFileNameW(NULL, szExePath, MAX_PATH)) {
        dwError = GetLastError();
        log_error("GetModuleFileName failed: %lu", dwError);
        return FALSE;
    }
    
    swprintf(szCmdLine, sizeof(szCmdLine)/sizeof(WCHAR), L"\"%s\" %S", szExePath, KEYBOARD_HOOK_FLAG);
    
    si.cb = sizeof(si);
    si.lpDesktop = L"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        dwError = GetLastError();
        log_error("WTSQueryUserToken failed for session %lu: %lu", sessionId, dwError);
        return FALSE;
    }
    
    // Duplicate token with elevated privileges
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        dwError = GetLastError();
        log_error("DuplicateTokenEx failed: %lu", dwError);
        goto cleanup;
    }
    
    // Try to get the linked token (elevated version) if available
    TOKEN_LINKED_TOKEN linkedToken = {0};
    DWORD dwSize = 0;
    
    if (GetTokenInformation(hDupToken, TokenLinkedToken, &linkedToken, sizeof(linkedToken), &dwSize)) {
        if (linkedToken.LinkedToken) {
            // Use the linked (elevated) token instead
            CloseHandle(hDupToken);
            hDupToken = linkedToken.LinkedToken;
        }
    }
    
    if (!CreateEnvironmentBlock(&pEnvironment, hDupToken, FALSE)) {
        dwError = GetLastError();
        log_error("CreateEnvironmentBlock failed: %lu", dwError);
        goto cleanup;
    }
    
    bResult = CreateProcessAsUserW(
        hDupToken, NULL, szCmdLine, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        pEnvironment, NULL, &si, &pi
    );
    
    if (bResult) {
        // Get username for this session
        char username[256] = {0};
        DWORD usernameLen = 0;
        LPWSTR pUsername = NULL;
        
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &pUsername, &usernameLen)) {
            int result = WideCharToMultiByte(CP_UTF8, 0, pUsername, -1, username, sizeof(username), NULL, NULL);
            WTSFreeMemory(pUsername);
            
            if (result > 0) {
                log_info("Attaching keyboard helper to logged in user %s", username);
            } else {
                log_info("Attaching keyboard helper to session %lu", sessionId);
            }
        } else {
            log_info("Attaching keyboard helper to session %lu", sessionId);
        }
        
		if (outProcess)
			*outProcess = pi.hProcess;
		else
			CloseHandle(pi.hProcess);

		CloseHandle(pi.hThread);
    } else {
        dwError = GetLastError();
        log_error("CreateProcessAsUserW failed: %lu", dwError);
    }
    
cleanup:
    if (pEnvironment) DestroyEnvironmentBlock(pEnvironment);
    if (hDupToken) CloseHandle(hDupToken);
    if (hToken) CloseHandle(hToken);
    return bResult;
}

static int find_helper_index_nolock(DWORD sessionId) {
	for (DWORD i = 0; i < g_HelperProcCount; i++) {
		if (g_HelperProcs[i].sessionId == sessionId)
			return (int)i;
	}
	return -1;
}

static BOOL is_helper_process_alive(HANDLE hProcess) {
	if (!hProcess || hProcess == HELPER_HANDLE_LAUNCHING)
		return FALSE;
	DWORD rc = WaitForSingleObject(hProcess, 0);
	return (rc == WAIT_TIMEOUT);
}

static void remove_helper_nolock(DWORD index, BOOL terminate) {
	HANDLE h = g_HelperProcs[index].hProcess;
	if (terminate && h && h != HELPER_HANDLE_LAUNCHING) {
		TerminateProcess(h, 0);
		WaitForSingleObject(h, 2000);
	}
	if (h && h != HELPER_HANDLE_LAUNCHING)
		CloseHandle(h);

	for (DWORD k = index; k < g_HelperProcCount - 1; k++)
		g_HelperProcs[k] = g_HelperProcs[k + 1];
	g_HelperProcCount--;
}

static void cleanup_helpers(void) {
	PWTS_SESSION_INFOW pSessions = NULL;
	DWORD sessionCount = 0;

	if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &sessionCount))
		return;

	EnterCriticalSection(&g_SessionLock);

	for (DWORD i = 0; i < g_HelperProcCount; ) {
		DWORD sid = g_HelperProcs[i].sessionId;
		BOOL sessionActive = FALSE;

		for (DWORD j = 0; j < sessionCount; j++) {
			if (pSessions[j].SessionId == sid && pSessions[j].State == WTSActive) {
				sessionActive = TRUE;
				break;
			}
		}

		if (!sessionActive) {
			remove_helper_nolock(i, TRUE);
			continue;
		}

		if (g_HelperProcs[i].hProcess != HELPER_HANDLE_LAUNCHING &&
			!is_helper_process_alive(g_HelperProcs[i].hProcess)) {
			remove_helper_nolock(i, FALSE);
			continue;
		}

		i++;
	}

	LeaveCriticalSection(&g_SessionLock);
	WTSFreeMemory(pSessions);
}

// Monitor for new sessions and attach keyboard hooks
static DWORD WINAPI session_monitor_thread(LPVOID param) {
	DWORD iterationCount = 0;

	do {
		PWTS_SESSION_INFOW pSessions = NULL;
		DWORD sessionCount = 0;

		if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &sessionCount))
			continue;

		for (DWORD i = 0; i < sessionCount; i++) {
			DWORD sid = pSessions[i].SessionId;
			if (pSessions[i].State != WTSActive)
				continue;

			BOOL reserved = FALSE;

			EnterCriticalSection(&g_SessionLock);

			int idx = find_helper_index_nolock(sid);
			if (idx >= 0) {
				HANDLE h = g_HelperProcs[idx].hProcess;
				if (h == HELPER_HANDLE_LAUNCHING) {
					LeaveCriticalSection(&g_SessionLock);
					continue;
				}
				if (is_helper_process_alive(h)) {
					LeaveCriticalSection(&g_SessionLock);
					continue;
				}
				remove_helper_nolock((DWORD)idx, FALSE);
				idx = -1;
			}

			if (idx < 0) {
				if (g_HelperProcCount < MAX_TRACKED_SESSIONS) {
					g_HelperProcs[g_HelperProcCount].sessionId = sid;
					g_HelperProcs[g_HelperProcCount].hProcess = HELPER_HANDLE_LAUNCHING;
					g_HelperProcCount++;
					reserved = TRUE;
				} else {
					log_error("Maximum tracked sessions (%d) exceeded. Cannot track session %lu", MAX_TRACKED_SESSIONS, sid);
				}
			}

			LeaveCriticalSection(&g_SessionLock);

			if (reserved) {
				HANDLE hProc = NULL;
				if (launch_keyboard_hook_in_session(sid, &hProc) && hProc) {
					EnterCriticalSection(&g_SessionLock);
					int j = find_helper_index_nolock(sid);
					if (j >= 0) {
						g_HelperProcs[j].hProcess = hProc;
					} else if (g_HelperProcCount < MAX_TRACKED_SESSIONS) {
						g_HelperProcs[g_HelperProcCount].sessionId = sid;
						g_HelperProcs[g_HelperProcCount].hProcess = hProc;
						g_HelperProcCount++;
					} else {
						CloseHandle(hProc);
					}
					LeaveCriticalSection(&g_SessionLock);
				} else {
					EnterCriticalSection(&g_SessionLock);
					int j = find_helper_index_nolock(sid);
					if (j >= 0 && g_HelperProcs[j].hProcess == HELPER_HANDLE_LAUNCHING)
						remove_helper_nolock((DWORD)j, FALSE);
					LeaveCriticalSection(&g_SessionLock);
				}
			}
		}

		WTSFreeMemory(pSessions);

		iterationCount++;
		if (iterationCount >= 6) {
			cleanup_helpers();
			iterationCount = 0;
		}

	} while (WaitForSingleObject(g_ServiceStopEvent, SESSION_POLL_INTERVAL_MS) == WAIT_TIMEOUT);

	return 0;
}

// Minimal HTTP server thread
static DWORD WINAPI http_server_thread(LPVOID param) {
    WSADATA wsa;
    SOCKET listenSocket = INVALID_SOCKET, clientSocket;
    struct sockaddr_in addr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];
    DWORD dwError;
    
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        log_error("WSAStartup failed");
        return 1;
    }
    
    if ((listenSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        log_error("Socket creation failed");
        goto cleanup;
    }
    
    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, g_bindIP, &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)g_bindPort);
    
    if (bind(listenSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        dwError = WSAGetLastError();
        log_error("Bind failed on port %lu: %d", g_bindPort, dwError);
        goto cleanup;
    }
    
    if (listen(listenSocket, 3) == SOCKET_ERROR) {
        dwError = WSAGetLastError();
        log_error("Listen failed: %d", dwError);
        goto cleanup;
    }
    
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        fd_set readfds;
        struct timeval tv = {0, HTTP_SELECT_TIMEOUT_MS * 1000};
        
        FD_ZERO(&readfds);
        FD_SET(listenSocket, &readfds);
        
        if (select(listenSocket + 1, &readfds, NULL, NULL, &tv) > 0) {
            if ((clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen)) != INVALID_SOCKET) {
                int recvSize = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
                if (recvSize > 0) {
                    buffer[recvSize] = '\0';
                    
                    // Check if request starts with "GET /lock"
                    if (recvSize >= 9 && strncmp(buffer, "GET /lock", 9) == 0) {
                        log_info("Received API request /lock");
                        lock_all_sessions();
                        const char* response = 
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "{\"status\":\"ok\",\"message\":\"Sessions locked\"}\r\n";
                        send(clientSocket, response, strlen(response), 0);
                    } else {
                        const char* response = 
                            "HTTP/1.1 404 Not Found\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n"
                            "\r\n"
                            "{\"status\":\"error\",\"message\":\"Endpoint not found\"}\r\n";
                        send(clientSocket, response, strlen(response), 0);
                    }
                }
                closesocket(clientSocket);
            }
        }
    }
    
cleanup:
    if (listenSocket != INVALID_SOCKET) closesocket(listenSocket);
    WSACleanup();
    return 0;
}

// Service control handler
static void WINAPI service_ctrl_handler(DWORD ctrl) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_ServiceStopEvent);
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            break;
    }
}

// Load bind settings from registry
static void load_settings(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type, size;

        size = sizeof(g_bindIP);
        if (RegQueryValueExA(hKey, REG_VALUE_BIND_IP, NULL, &type, (BYTE*)g_bindIP, &size) != ERROR_SUCCESS
            || type != REG_SZ || size == 0) {
            strcpy(g_bindIP, "0.0.0.0");
        }
        g_bindIP[sizeof(g_bindIP) - 1] = '\0';

        DWORD port = 0;
        size = sizeof(port);
        if (RegQueryValueExA(hKey, REG_VALUE_BIND_PORT, NULL, &type, (BYTE*)&port, &size) == ERROR_SUCCESS
            && type == REG_DWORD && port >= 1 && port <= 65535) {
            g_bindPort = port;
        }

        DWORD val = 0;
        size = sizeof(val);
        if (RegQueryValueExA(hKey, REG_VALUE_ENABLE_HTTP, NULL, &type, (BYTE*)&val, &size) == ERROR_SUCCESS
            && type == REG_DWORD) {
            g_enableHTTP = val ? 1 : 0;
        } else {
            g_enableHTTP = 1;
        }

        val = 0;
        size = sizeof(val);
        if (RegQueryValueExA(hKey, REG_VALUE_ENABLE_MONOFF, NULL, &type, (BYTE*)&val, &size) == ERROR_SUCCESS
            && type == REG_DWORD) {
            g_enableMonitorOff = val ? 1 : 0;
        } else {
            g_enableMonitorOff = 1;
        }

        RegCloseKey(hKey);
    }
}

// Save bind settings to registry
static BOOL save_settings(const char* ip, DWORD port, DWORD enableHTTP, DWORD enableMonOff) {
    HKEY hKey;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disp) != ERROR_SUCCESS)
        return FALSE;

    BOOL ok = TRUE;
    if (RegSetValueExA(hKey, REG_VALUE_BIND_IP, 0, REG_SZ, (const BYTE*)ip, (DWORD)strlen(ip) + 1) != ERROR_SUCCESS)
        ok = FALSE;
    if (RegSetValueExA(hKey, REG_VALUE_BIND_PORT, 0, REG_DWORD, (const BYTE*)&port, sizeof(port)) != ERROR_SUCCESS)
        ok = FALSE;
    if (RegSetValueExA(hKey, REG_VALUE_ENABLE_HTTP, 0, REG_DWORD, (const BYTE*)&enableHTTP, sizeof(enableHTTP)) != ERROR_SUCCESS)
        ok = FALSE;
    if (RegSetValueExA(hKey, REG_VALUE_ENABLE_MONOFF, 0, REG_DWORD, (const BYTE*)&enableMonOff, sizeof(enableMonOff)) != ERROR_SUCCESS)
        ok = FALSE;

    if (ok) {
        g_enableHTTP = enableHTTP;
        g_enableMonitorOff = enableMonOff;
    }

    RegCloseKey(hKey);
    return ok;
}

// Service main function
static void WINAPI service_main(DWORD argc, LPWSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(L"LockService", service_ctrl_handler);
    if (!g_StatusHandle) return;
    
    memset(&g_ServiceStatus, 0, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // Initialize event logging
    g_hEventLog = RegisterEventSourceA(NULL, SERVICE_NAME);
    
    g_ServiceStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        if (g_hEventLog) DeregisterEventSource(g_hEventLog);
        return;
    }
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // Initialize session tracking
    InitializeCriticalSection(&g_SessionLock);
    g_HelperProcCount = 0;

    // Load bind settings from registry
    load_settings();

    // Start HTTP server thread (if enabled)
    HANDLE hHttpThread = NULL;
    if (g_enableHTTP) {
        hHttpThread = CreateThread(NULL, 0, http_server_thread, NULL, 0, NULL);
        if (!hHttpThread) {
            DWORD dwError = GetLastError();
            log_error("Failed to create HTTP server thread: %lu", dwError);
            DeleteCriticalSection(&g_SessionLock);
            CloseHandle(g_ServiceStopEvent);
            if (g_hEventLog) DeregisterEventSource(g_hEventLog);
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            g_ServiceStatus.dwWin32ExitCode = dwError;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            return;
        }
    }
    
    // Start session monitoring thread (does immediate check, then every 10 seconds)
    HANDLE hMonitorThread = CreateThread(NULL, 0, session_monitor_thread, NULL, 0, NULL);
    if (!hMonitorThread) {
        DWORD dwError = GetLastError();
        log_error("Failed to create session monitor thread: %lu", dwError);
        SetEvent(g_ServiceStopEvent);
        if (hHttpThread) {
            WaitForSingleObject(hHttpThread, THREAD_SHUTDOWN_TIMEOUT_MS);
            CloseHandle(hHttpThread);
        }
        DeleteCriticalSection(&g_SessionLock);
        CloseHandle(g_ServiceStopEvent);
        if (g_hEventLog) DeregisterEventSource(g_hEventLog);
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = dwError;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);
    
// Terminate all helper processes before shutting down threads
    EnterCriticalSection(&g_SessionLock);
    for (DWORD i = 0; i < g_HelperProcCount; i++) {
        HANDLE h = g_HelperProcs[i].hProcess;
        if (h && h != HELPER_HANDLE_LAUNCHING) {
            if (TerminateProcess(h, 0)) {
                WaitForSingleObject(h, 2000);
            }
            CloseHandle(h);
        }
    }
    g_HelperProcCount = 0;
    LeaveCriticalSection(&g_SessionLock);
    
    if (hHttpThread) {
        WaitForSingleObject(hHttpThread, THREAD_SHUTDOWN_TIMEOUT_MS);
        CloseHandle(hHttpThread);
    }
    if (hMonitorThread) {
        WaitForSingleObject(hMonitorThread, THREAD_SHUTDOWN_TIMEOUT_MS);
        CloseHandle(hMonitorThread);
    }
    
    DeleteCriticalSection(&g_SessionLock);
    CloseHandle(g_ServiceStopEvent);
    
    if (g_hEventLog) {
        DeregisterEventSource(g_hEventLog);
    }
    
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// Kill all other LockService.exe instances (helpers, hooks, service) except ourselves
static void kill_other_instances(void) {
    DWORD myPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    WCHAR myExe[MAX_PATH];
    GetModuleFileNameW(NULL, myExe, MAX_PATH);
    WCHAR *myName = wcsrchr(myExe, L'\\');
    myName = myName ? myName + 1 : myExe;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID != myPid && _wcsicmp(pe.szExeFile, myName) == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    WaitForSingleObject(hProc, 2000);
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
}

// Install the service
static BOOL install_service(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    WCHAR szPath[MAX_PATH];
    BOOL bResult = FALSE;
    
    if (!GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        fprintf(stderr, "Cannot get module filename\n");
        return FALSE;
    }
    
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    svc = CreateServiceW(
        scm, L"LockService", SERVICE_DISPLAY_NAME_W,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        szPath, NULL, NULL, NULL, NULL, NULL
    );
    
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "Service already exists\n");
        } else {
            fprintf(stderr, "CreateService failed: %lu\n", err);
        }
        goto cleanup;
    }
    
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = L"Locks workstations and turns off monitors via HTTP API and Win+L hotkey interception.";
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    printf("Service installed successfully\n");
    printf("Service will start automatically on boot\n");
    printf("To start now: sc start %s\n", SERVICE_NAME);
    printf("To stop: sc stop %s\n", SERVICE_NAME);
    bResult = TRUE;
    
cleanup:
    if (svc) CloseServiceHandle(svc);
    if (scm) CloseServiceHandle(scm);
    return bResult;
}

// Uninstall the service
static BOOL uninstall_service(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    SERVICE_STATUS status;
    BOOL bResult = FALSE;
    
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    svc = OpenServiceW(scm, L"LockService", SERVICE_STOP | DELETE);
    if (!svc) {
        fprintf(stderr, "OpenService failed: %lu\n", GetLastError());
        goto cleanup;
    }
    
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);
    kill_other_instances();

    if (DeleteService(svc)) {
        printf("Service uninstalled successfully\n");
        bResult = TRUE;
    } else {
        fprintf(stderr, "DeleteService failed: %lu\n", GetLastError());
    }
    
cleanup:
    if (svc) CloseServiceHandle(svc);
    if (scm) CloseServiceHandle(scm);
    return bResult;
}

// Start the service via SCM
static BOOL start_service(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    BOOL bResult = FALSE;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    svc = OpenServiceW(scm, L"LockService", SERVICE_START);
    if (!svc) goto cleanup;

    bResult = StartServiceW(svc, 0, NULL);

cleanup:
    if (svc) CloseServiceHandle(svc);
    if (scm) CloseServiceHandle(scm);
    return bResult;
}

// Stop the service via SCM and kill all remaining instances
static BOOL stop_service(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    SERVICE_STATUS status;
    BOOL bResult = FALSE;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    svc = OpenServiceW(scm, L"LockService", SERVICE_STOP);
    if (!svc) goto cleanup;

    bResult = ControlService(svc, SERVICE_CONTROL_STOP, &status);

cleanup:
    if (svc) CloseServiceHandle(svc);
    if (scm) CloseServiceHandle(scm);

    // Ensure all other instances (service, helpers, hooks) are terminated
    Sleep(500);
    kill_other_instances();

    return bResult;
}

// Restart the service (stop then start)
static BOOL restart_service(void) {
    stop_service();
    Sleep(500);
    return start_service();
}

// Query service state: 0=not installed, 1=stopped, 2=running, 3=transitioning
static int query_service_state(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    SERVICE_STATUS status;
    int result = 0;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    svc = OpenServiceW(scm, L"LockService", SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return 0;
    }

    if (QueryServiceStatus(svc, &status)) {
        switch (status.dwCurrentState) {
            case SERVICE_STOPPED:
                result = 1;
                break;
            case SERVICE_RUNNING:
                result = 2;
                break;
            default:
                result = 3;
                break;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return result;
}

// ============================================================================
// WebView2 COM interface definitions (minimal vtable approach)
// ============================================================================

// GUIDs
DEFINE_GUID(IID_ICoreWebView2Environment, 0xb96d755e,0x0319,0x4e92,0xa2,0x96,0x23,0x43,0x6f,0x46,0xa1,0xfc);
DEFINE_GUID(IID_ICoreWebView2Controller, 0x4d00c0d1,0x9583,0x4f38,0x8e,0x50,0xa9,0xa6,0xb3,0x44,0x78,0xcd);
DEFINE_GUID(IID_ICoreWebView2, 0x76eceacb,0x0462,0x4d94,0xac,0x83,0x42,0x3a,0x67,0x93,0x77,0x5e);
DEFINE_GUID(IID_ICoreWebView2Settings, 0xe562e4f0,0xd7fa,0x43ac,0x8d,0x71,0xc0,0x51,0x50,0x49,0x9f,0x00);

typedef struct EventRegistrationToken { __int64 value; } EventRegistrationToken;

// Forward declarations of COM interfaces
typedef struct ICoreWebView2Environment ICoreWebView2Environment;
typedef struct ICoreWebView2Controller ICoreWebView2Controller;
typedef struct ICoreWebView2 ICoreWebView2;
typedef struct ICoreWebView2Settings ICoreWebView2Settings;
typedef struct ICoreWebView2WebMessageReceivedEventArgs ICoreWebView2WebMessageReceivedEventArgs;
typedef struct ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;
typedef struct ICoreWebView2CreateCoreWebView2ControllerCompletedHandler ICoreWebView2CreateCoreWebView2ControllerCompletedHandler;
typedef struct ICoreWebView2WebMessageReceivedEventHandler ICoreWebView2WebMessageReceivedEventHandler;

// ICoreWebView2Environment vtable
typedef struct ICoreWebView2EnvironmentVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2Environment*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2Environment*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2Environment*);
    // ICoreWebView2Environment
    HRESULT (STDMETHODCALLTYPE *CreateCoreWebView2Controller)(ICoreWebView2Environment*, HWND, ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*);
    HRESULT (STDMETHODCALLTYPE *CreateWebResourceResponse)(ICoreWebView2Environment*, void*, int, LPCWSTR, LPCWSTR, void**);
    HRESULT (STDMETHODCALLTYPE *get_BrowserVersionString)(ICoreWebView2Environment*, LPWSTR*);
    HRESULT (STDMETHODCALLTYPE *add_NewBrowserVersionAvailable)(ICoreWebView2Environment*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_NewBrowserVersionAvailable)(ICoreWebView2Environment*, EventRegistrationToken);
} ICoreWebView2EnvironmentVtbl;

struct ICoreWebView2Environment { const ICoreWebView2EnvironmentVtbl *lpVtbl; };

// ICoreWebView2Controller vtable
typedef struct ICoreWebView2ControllerVtbl {
    // IUnknown
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2Controller*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2Controller*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2Controller*);
    // ICoreWebView2Controller
    HRESULT (STDMETHODCALLTYPE *get_IsVisible)(ICoreWebView2Controller*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsVisible)(ICoreWebView2Controller*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_Bounds)(ICoreWebView2Controller*, RECT*);
    HRESULT (STDMETHODCALLTYPE *put_Bounds)(ICoreWebView2Controller*, RECT);
    HRESULT (STDMETHODCALLTYPE *get_ZoomFactor)(ICoreWebView2Controller*, double*);
    HRESULT (STDMETHODCALLTYPE *put_ZoomFactor)(ICoreWebView2Controller*, double);
    HRESULT (STDMETHODCALLTYPE *add_ZoomFactorChanged)(ICoreWebView2Controller*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_ZoomFactorChanged)(ICoreWebView2Controller*, EventRegistrationToken);
    HRESULT (STDMETHODCALLTYPE *SetBoundsAndZoomFactor)(ICoreWebView2Controller*, RECT, double);
    HRESULT (STDMETHODCALLTYPE *MoveFocus)(ICoreWebView2Controller*, int);
    HRESULT (STDMETHODCALLTYPE *add_MoveFocusRequested)(ICoreWebView2Controller*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_MoveFocusRequested)(ICoreWebView2Controller*, EventRegistrationToken);
    HRESULT (STDMETHODCALLTYPE *add_GotFocus)(ICoreWebView2Controller*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_GotFocus)(ICoreWebView2Controller*, EventRegistrationToken);
    HRESULT (STDMETHODCALLTYPE *add_LostFocus)(ICoreWebView2Controller*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_LostFocus)(ICoreWebView2Controller*, EventRegistrationToken);
    HRESULT (STDMETHODCALLTYPE *add_AcceleratorKeyPressed)(ICoreWebView2Controller*, void*, EventRegistrationToken*);
    HRESULT (STDMETHODCALLTYPE *remove_AcceleratorKeyPressed)(ICoreWebView2Controller*, EventRegistrationToken);
    HRESULT (STDMETHODCALLTYPE *get_ParentWindow)(ICoreWebView2Controller*, HWND*);
    HRESULT (STDMETHODCALLTYPE *put_ParentWindow)(ICoreWebView2Controller*, HWND);
    HRESULT (STDMETHODCALLTYPE *NotifyParentWindowPositionChanged)(ICoreWebView2Controller*);
    HRESULT (STDMETHODCALLTYPE *Close)(ICoreWebView2Controller*);
    HRESULT (STDMETHODCALLTYPE *get_CoreWebView2)(ICoreWebView2Controller*, ICoreWebView2**);
} ICoreWebView2ControllerVtbl;

struct ICoreWebView2Controller { const ICoreWebView2ControllerVtbl *lpVtbl; };

// ICoreWebView2 vtable (we only need a few methods but must fill the full table)
typedef struct ICoreWebView2Vtbl {
    // IUnknown (3)
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2*);
    // ICoreWebView2 methods (indices 3..61)
    HRESULT (STDMETHODCALLTYPE *get_Settings)(ICoreWebView2*, ICoreWebView2Settings**);                        // 3
    HRESULT (STDMETHODCALLTYPE *get_Source)(ICoreWebView2*, LPWSTR*);                                          // 4
    HRESULT (STDMETHODCALLTYPE *Navigate)(ICoreWebView2*, LPCWSTR);                                            // 5
    HRESULT (STDMETHODCALLTYPE *NavigateToString)(ICoreWebView2*, LPCWSTR);                                    // 6
    HRESULT (STDMETHODCALLTYPE *add_NavigationStarting)(ICoreWebView2*, void*, EventRegistrationToken*);       // 7
    HRESULT (STDMETHODCALLTYPE *remove_NavigationStarting)(ICoreWebView2*, EventRegistrationToken);            // 8
    HRESULT (STDMETHODCALLTYPE *add_ContentLoading)(ICoreWebView2*, void*, EventRegistrationToken*);           // 9
    HRESULT (STDMETHODCALLTYPE *remove_ContentLoading)(ICoreWebView2*, EventRegistrationToken);                // 10
    HRESULT (STDMETHODCALLTYPE *add_SourceChanged)(ICoreWebView2*, void*, EventRegistrationToken*);            // 11
    HRESULT (STDMETHODCALLTYPE *remove_SourceChanged)(ICoreWebView2*, EventRegistrationToken);                 // 12
    HRESULT (STDMETHODCALLTYPE *add_HistoryChanged)(ICoreWebView2*, void*, EventRegistrationToken*);           // 13
    HRESULT (STDMETHODCALLTYPE *remove_HistoryChanged)(ICoreWebView2*, EventRegistrationToken);                // 14
    HRESULT (STDMETHODCALLTYPE *add_NavigationCompleted)(ICoreWebView2*, void*, EventRegistrationToken*);      // 15
    HRESULT (STDMETHODCALLTYPE *remove_NavigationCompleted)(ICoreWebView2*, EventRegistrationToken);           // 16
    HRESULT (STDMETHODCALLTYPE *add_FrameNavigationStarting)(ICoreWebView2*, void*, EventRegistrationToken*);  // 17
    HRESULT (STDMETHODCALLTYPE *remove_FrameNavigationStarting)(ICoreWebView2*, EventRegistrationToken);       // 18
    HRESULT (STDMETHODCALLTYPE *add_FrameNavigationCompleted)(ICoreWebView2*, void*, EventRegistrationToken*); // 19
    HRESULT (STDMETHODCALLTYPE *remove_FrameNavigationCompleted)(ICoreWebView2*, EventRegistrationToken);      // 20
    HRESULT (STDMETHODCALLTYPE *add_ScriptDialogOpening)(ICoreWebView2*, void*, EventRegistrationToken*);      // 21
    HRESULT (STDMETHODCALLTYPE *remove_ScriptDialogOpening)(ICoreWebView2*, EventRegistrationToken);           // 22
    HRESULT (STDMETHODCALLTYPE *add_PermissionRequested)(ICoreWebView2*, void*, EventRegistrationToken*);      // 23
    HRESULT (STDMETHODCALLTYPE *remove_PermissionRequested)(ICoreWebView2*, EventRegistrationToken);           // 24
    HRESULT (STDMETHODCALLTYPE *add_ProcessFailed)(ICoreWebView2*, void*, EventRegistrationToken*);            // 25
    HRESULT (STDMETHODCALLTYPE *remove_ProcessFailed)(ICoreWebView2*, EventRegistrationToken);                 // 26
    HRESULT (STDMETHODCALLTYPE *AddScriptToExecuteOnDocumentCreated)(ICoreWebView2*, LPCWSTR, void*);          // 27
    HRESULT (STDMETHODCALLTYPE *RemoveScriptToExecuteOnDocumentCreated)(ICoreWebView2*, LPCWSTR);              // 28
    HRESULT (STDMETHODCALLTYPE *ExecuteScript)(ICoreWebView2*, LPCWSTR, void*);                                // 29
    HRESULT (STDMETHODCALLTYPE *CapturePreview)(ICoreWebView2*, int, void*, void*);                            // 30
    HRESULT (STDMETHODCALLTYPE *Reload)(ICoreWebView2*);                                                       // 31
    HRESULT (STDMETHODCALLTYPE *PostWebMessageAsJson)(ICoreWebView2*, LPCWSTR);                                // 32
    HRESULT (STDMETHODCALLTYPE *PostWebMessageAsString)(ICoreWebView2*, LPCWSTR);                              // 33
    HRESULT (STDMETHODCALLTYPE *add_WebMessageReceived)(ICoreWebView2*, ICoreWebView2WebMessageReceivedEventHandler*, EventRegistrationToken*); // 34
    HRESULT (STDMETHODCALLTYPE *remove_WebMessageReceived)(ICoreWebView2*, EventRegistrationToken);            // 35
    HRESULT (STDMETHODCALLTYPE *CallDevToolsProtocolMethod)(ICoreWebView2*, LPCWSTR, LPCWSTR, void*);         // 36
    HRESULT (STDMETHODCALLTYPE *get_BrowserProcessId)(ICoreWebView2*, UINT32*);                                // 37
    HRESULT (STDMETHODCALLTYPE *get_CanGoBack)(ICoreWebView2*, BOOL*);                                         // 38
    HRESULT (STDMETHODCALLTYPE *get_CanGoForward)(ICoreWebView2*, BOOL*);                                      // 39
    HRESULT (STDMETHODCALLTYPE *GoBack)(ICoreWebView2*);                                                       // 40
    HRESULT (STDMETHODCALLTYPE *GoForward)(ICoreWebView2*);                                                    // 41
    HRESULT (STDMETHODCALLTYPE *GetDevToolsProtocolEventReceiver)(ICoreWebView2*, LPCWSTR, void**);            // 42
    HRESULT (STDMETHODCALLTYPE *Stop)(ICoreWebView2*);                                                         // 43
    HRESULT (STDMETHODCALLTYPE *add_NewWindowRequested)(ICoreWebView2*, void*, EventRegistrationToken*);       // 44
    HRESULT (STDMETHODCALLTYPE *remove_NewWindowRequested)(ICoreWebView2*, EventRegistrationToken);            // 45
    HRESULT (STDMETHODCALLTYPE *add_DocumentTitleChanged)(ICoreWebView2*, void*, EventRegistrationToken*);     // 46
    HRESULT (STDMETHODCALLTYPE *remove_DocumentTitleChanged)(ICoreWebView2*, EventRegistrationToken);          // 47
    HRESULT (STDMETHODCALLTYPE *get_DocumentTitle)(ICoreWebView2*, LPWSTR*);                                   // 48
    HRESULT (STDMETHODCALLTYPE *AddHostObjectToScript)(ICoreWebView2*, LPCWSTR, void*);                        // 49
    HRESULT (STDMETHODCALLTYPE *RemoveHostObjectFromScript)(ICoreWebView2*, LPCWSTR);                          // 50
    HRESULT (STDMETHODCALLTYPE *OpenDevToolsWindow)(ICoreWebView2*);                                           // 51
    HRESULT (STDMETHODCALLTYPE *add_ContainsFullScreenElementChanged)(ICoreWebView2*, void*, EventRegistrationToken*); // 52
    HRESULT (STDMETHODCALLTYPE *remove_ContainsFullScreenElementChanged)(ICoreWebView2*, EventRegistrationToken); // 53
    HRESULT (STDMETHODCALLTYPE *get_ContainsFullScreenElement)(ICoreWebView2*, BOOL*);                         // 54
    HRESULT (STDMETHODCALLTYPE *add_WebResourceRequested)(ICoreWebView2*, void*, EventRegistrationToken*);     // 55
    HRESULT (STDMETHODCALLTYPE *remove_WebResourceRequested)(ICoreWebView2*, EventRegistrationToken);          // 56
    HRESULT (STDMETHODCALLTYPE *AddWebResourceRequestedFilter)(ICoreWebView2*, LPCWSTR, int);                  // 57
    HRESULT (STDMETHODCALLTYPE *RemoveWebResourceRequestedFilter)(ICoreWebView2*, LPCWSTR, int);               // 58
    HRESULT (STDMETHODCALLTYPE *add_WindowCloseRequested)(ICoreWebView2*, void*, EventRegistrationToken*);     // 59
    HRESULT (STDMETHODCALLTYPE *remove_WindowCloseRequested)(ICoreWebView2*, EventRegistrationToken);          // 60
} ICoreWebView2Vtbl;

struct ICoreWebView2 { const ICoreWebView2Vtbl *lpVtbl; };

// ICoreWebView2Settings vtable
typedef struct ICoreWebView2SettingsVtbl {
    // IUnknown (3)
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2Settings*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2Settings*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2Settings*);
    // ICoreWebView2Settings
    HRESULT (STDMETHODCALLTYPE *get_IsScriptEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsScriptEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_IsWebMessageEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsWebMessageEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_AreDefaultScriptDialogsEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_AreDefaultScriptDialogsEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_IsStatusBarEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsStatusBarEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_AreDevToolsEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_AreDevToolsEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_AreDefaultContextMenusEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_AreDefaultContextMenusEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_AreHostObjectsAllowed)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_AreHostObjectsAllowed)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_IsZoomControlEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsZoomControlEnabled)(ICoreWebView2Settings*, BOOL);
    HRESULT (STDMETHODCALLTYPE *get_IsBuiltInErrorPageEnabled)(ICoreWebView2Settings*, BOOL*);
    HRESULT (STDMETHODCALLTYPE *put_IsBuiltInErrorPageEnabled)(ICoreWebView2Settings*, BOOL);
} ICoreWebView2SettingsVtbl;

struct ICoreWebView2Settings { const ICoreWebView2SettingsVtbl *lpVtbl; };

// ICoreWebView2WebMessageReceivedEventArgs vtable
typedef struct ICoreWebView2WebMessageReceivedEventArgsVtbl {
    // IUnknown (3)
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2WebMessageReceivedEventArgs*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2WebMessageReceivedEventArgs*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2WebMessageReceivedEventArgs*);
    // ICoreWebView2WebMessageReceivedEventArgs
    HRESULT (STDMETHODCALLTYPE *get_Source)(ICoreWebView2WebMessageReceivedEventArgs*, LPWSTR*);
    HRESULT (STDMETHODCALLTYPE *get_WebMessageAsJson)(ICoreWebView2WebMessageReceivedEventArgs*, LPWSTR*);
    HRESULT (STDMETHODCALLTYPE *TryGetWebMessageAsString)(ICoreWebView2WebMessageReceivedEventArgs*, LPWSTR*);
} ICoreWebView2WebMessageReceivedEventArgsVtbl;

struct ICoreWebView2WebMessageReceivedEventArgs { const ICoreWebView2WebMessageReceivedEventArgsVtbl *lpVtbl; };

// ============================================================================
// COM callback handler types
// ============================================================================

// Handler vtable types
typedef struct EnvironmentCompletedHandlerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*, HRESULT, ICoreWebView2Environment*);
} EnvironmentCompletedHandlerVtbl;

struct ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
    const EnvironmentCompletedHandlerVtbl *lpVtbl;
    ULONG refCount;
};

typedef struct ControllerCompletedHandlerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*, HRESULT, ICoreWebView2Controller*);
} ControllerCompletedHandlerVtbl;

struct ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
    const ControllerCompletedHandlerVtbl *lpVtbl;
    ULONG refCount;
};

typedef struct WebMessageReceivedHandlerVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICoreWebView2WebMessageReceivedEventHandler*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICoreWebView2WebMessageReceivedEventHandler*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICoreWebView2WebMessageReceivedEventHandler*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICoreWebView2WebMessageReceivedEventHandler*, ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs*);
} WebMessageReceivedHandlerVtbl;

struct ICoreWebView2WebMessageReceivedEventHandler {
    const WebMessageReceivedHandlerVtbl *lpVtbl;
    ULONG refCount;
};

// ============================================================================
// WebView2 globals
// ============================================================================

static HWND g_hWnd = NULL;
static ICoreWebView2Environment *g_webviewEnv = NULL;
static ICoreWebView2Controller *g_webviewController = NULL;
static ICoreWebView2 *g_webviewView = NULL;

// Dynamic loader for WebView2Loader.dll
typedef HRESULT (STDAPICALLTYPE *PFN_CreateCoreWebView2EnvironmentWithOptions)(
    LPCWSTR browserExecutableFolder, LPCWSTR userDataFolder, void* options,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler* handler);

static PFN_CreateCoreWebView2EnvironmentWithOptions fnCreateEnvironment = NULL;

static WCHAR g_extractedDllPath[MAX_PATH] = {0};

static BOOL load_webview2_loader(void) {
    // Extract embedded WebView2Loader.dll from resources to %TEMP%
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_WEBVIEW2_DLL), RT_RCDATA);
    if (hRes) {
        HGLOBAL hData = LoadResource(NULL, hRes);
        DWORD dllSize = SizeofResource(NULL, hRes);
        const void *dllBytes = LockResource(hData);
        if (dllBytes && dllSize > 0) {
            WCHAR tempDir[MAX_PATH];
            DWORD tempLen = GetTempPathW(MAX_PATH, tempDir);
            if (tempLen > 0 && tempLen < MAX_PATH - 30) {
                swprintf(g_extractedDllPath, MAX_PATH, L"%sWebView2Loader.dll", tempDir);
                HANDLE hFile = CreateFileW(g_extractedDllPath, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hFile, dllBytes, dllSize, &written, NULL);
                    CloseHandle(hFile);
                    if (written == dllSize) {
                        HMODULE hMod = LoadLibraryW(g_extractedDllPath);
                        if (hMod) {
                            fnCreateEnvironment = (PFN_CreateCoreWebView2EnvironmentWithOptions)
                                GetProcAddress(hMod, "CreateCoreWebView2EnvironmentWithOptions");
                            if (fnCreateEnvironment) return TRUE;
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}

// ============================================================================
// Helper: Execute JS on the webview
// ============================================================================

static void webview_execute_script(const wchar_t* script) {
    if (g_webviewView) {
        g_webviewView->lpVtbl->ExecuteScript(g_webviewView, script, NULL);
    }
}

// Send settings to JS
static void webview_push_settings(void) {
    wchar_t script[512];
    wchar_t wIP[64];
    MultiByteToWideChar(CP_UTF8, 0, g_bindIP, -1, wIP, 64);
    swprintf(script, 512,
        L"window.onSettingsUpdate({\"bindIP\":\"%s\",\"bindPort\":%lu,\"enableHTTP\":%s,\"enableMonitorOff\":%s})",
        wIP, g_bindPort,
        g_enableHTTP ? L"true" : L"false",
        g_enableMonitorOff ? L"true" : L"false");
    webview_execute_script(script);
}

// Send service state to JS
static void webview_push_service_state(void) {
    int state = query_service_state();
    const wchar_t *label;
    switch (state) {
        case 0: label = L"Not Installed"; break;
        case 1: label = L"Stopped"; break;
        case 2: label = L"Running"; break;
        case 3: label = L"Transitioning..."; break;
        default: label = L"Unknown"; break;
    }
    wchar_t script[256];
    swprintf(script, 256,
        L"window.onServiceStateUpdate({\"state\":%d,\"label\":\"%s\"})",
        state, label);
    webview_execute_script(script);
}

// Send action result to JS
static void webview_push_action_result(const char *action, BOOL success) {
    wchar_t script[256];
    wchar_t wAction[64];
    MultiByteToWideChar(CP_UTF8, 0, action, -1, wAction, 64);
    swprintf(script, 256,
        L"window.onActionResult({\"action\":\"%s\",\"success\":%s})",
        wAction, success ? L"true" : L"false");
    webview_execute_script(script);
}

// ============================================================================
// Minimal JSON parser helpers (for parsing JS postMessage payloads)
// ============================================================================

// Find a string value for a key in a JSON-like string (narrow char)
static BOOL json_get_string(const char *json, const char *key, char *out, size_t outLen) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return FALSE;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return FALSE;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outLen - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return TRUE;
}

// Find a numeric value for a key
static BOOL json_get_int(const char *json, const char *key, int *out) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return FALSE;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    *out = atoi(p);
    return TRUE;
}

// Find a boolean value for a key
static BOOL json_get_bool(const char *json, const char *key, BOOL *out) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return FALSE;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    *out = (strncmp(p, "true", 4) == 0) ? TRUE : FALSE;
    return TRUE;
}

// ============================================================================
// COM callback handler implementations
// ============================================================================

// Forward declarations
static HRESULT STDMETHODCALLTYPE EnvCompleted_Invoke(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*, HRESULT, ICoreWebView2Environment*);
static HRESULT STDMETHODCALLTYPE CtrlCompleted_Invoke(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*, HRESULT, ICoreWebView2Controller*);
static HRESULT STDMETHODCALLTYPE MsgReceived_Invoke(ICoreWebView2WebMessageReceivedEventHandler*, ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs*);

// --- EnvironmentCompletedHandler ---

static HRESULT STDMETHODCALLTYPE EnvCompleted_QueryInterface(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This, REFIID riid, void **ppv) {
    (void)riid;
    *ppv = This;
    This->lpVtbl->AddRef(This);
    return S_OK;
}
static ULONG STDMETHODCALLTYPE EnvCompleted_AddRef(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This) {
    return ++This->refCount;
}
static ULONG STDMETHODCALLTYPE EnvCompleted_Release(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This) {
    ULONG rc = --This->refCount;
    if (rc == 0) free(This);
    return rc;
}
static HRESULT STDMETHODCALLTYPE EnvCompleted_Invoke(ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *This, HRESULT result, ICoreWebView2Environment *env) {
    (void)This;
    if (FAILED(result) || !env) return result;
    g_webviewEnv = env;
    env->lpVtbl->AddRef(env);

    // Allocate controller completed handler
    static ControllerCompletedHandlerVtbl ctrlVtbl = {0};
    static BOOL ctrlVtblInit = FALSE;
    if (!ctrlVtblInit) {
        ctrlVtbl.QueryInterface = (HRESULT (STDMETHODCALLTYPE *)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*, REFIID, void**))EnvCompleted_QueryInterface;
        ctrlVtbl.AddRef = (ULONG (STDMETHODCALLTYPE *)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*))EnvCompleted_AddRef;
        ctrlVtbl.Release = (ULONG (STDMETHODCALLTYPE *)(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*))EnvCompleted_Release;
        ctrlVtbl.Invoke = CtrlCompleted_Invoke;
        ctrlVtblInit = TRUE;
    }

    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *handler = malloc(sizeof(*handler));
    handler->lpVtbl = &ctrlVtbl;
    handler->refCount = 1;

    env->lpVtbl->CreateCoreWebView2Controller(env, g_hWnd, handler);
    handler->lpVtbl->Release(handler);
    return S_OK;
}

static EnvironmentCompletedHandlerVtbl g_envCompletedVtbl = {
    EnvCompleted_QueryInterface,
    EnvCompleted_AddRef,
    EnvCompleted_Release,
    EnvCompleted_Invoke
};

// --- ControllerCompletedHandler ---

static HRESULT STDMETHODCALLTYPE CtrlCompleted_Invoke(ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *This, HRESULT result, ICoreWebView2Controller *controller) {
    (void)This;
    if (FAILED(result) || !controller) return result;

    g_webviewController = controller;
    controller->lpVtbl->AddRef(controller);

    // Resize to fill window
    RECT bounds;
    GetClientRect(g_hWnd, &bounds);
    controller->lpVtbl->put_Bounds(controller, bounds);

    // Get the core webview
    ICoreWebView2 *webview = NULL;
    controller->lpVtbl->get_CoreWebView2(controller, &webview);
    if (!webview) return E_FAIL;
    g_webviewView = webview;

    // Configure settings
    ICoreWebView2Settings *settings = NULL;
    webview->lpVtbl->get_Settings(webview, &settings);
    if (settings) {
        settings->lpVtbl->put_AreDefaultContextMenusEnabled(settings, FALSE);
        settings->lpVtbl->put_AreDevToolsEnabled(settings, FALSE);
        settings->lpVtbl->put_IsStatusBarEnabled(settings, FALSE);
        settings->lpVtbl->put_IsZoomControlEnabled(settings, FALSE);
        settings->lpVtbl->Release(settings);
    }

    // Register web message handler
    static WebMessageReceivedHandlerVtbl msgVtbl = {0};
    static BOOL msgVtblInit = FALSE;
    if (!msgVtblInit) {
        msgVtbl.QueryInterface = (HRESULT (STDMETHODCALLTYPE *)(ICoreWebView2WebMessageReceivedEventHandler*, REFIID, void**))EnvCompleted_QueryInterface;
        msgVtbl.AddRef = (ULONG (STDMETHODCALLTYPE *)(ICoreWebView2WebMessageReceivedEventHandler*))EnvCompleted_AddRef;
        msgVtbl.Release = (ULONG (STDMETHODCALLTYPE *)(ICoreWebView2WebMessageReceivedEventHandler*))EnvCompleted_Release;
        msgVtbl.Invoke = MsgReceived_Invoke;
        msgVtblInit = TRUE;
    }

    ICoreWebView2WebMessageReceivedEventHandler *msgHandler = malloc(sizeof(*msgHandler));
    msgHandler->lpVtbl = &msgVtbl;
    msgHandler->refCount = 1;

    EventRegistrationToken token;
    webview->lpVtbl->add_WebMessageReceived(webview, msgHandler, &token);
    msgHandler->lpVtbl->Release(msgHandler);

    // Load embedded HTML from resources
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_HTML_UI), RT_RCDATA);
    if (hRes) {
        HGLOBAL hData = LoadResource(NULL, hRes);
        if (hData) {
            DWORD htmlSize = SizeofResource(NULL, hRes);
            const char *htmlUtf8 = (const char *)LockResource(hData);
            if (htmlUtf8 && htmlSize > 0) {
                int wLen = MultiByteToWideChar(CP_UTF8, 0, htmlUtf8, (int)htmlSize, NULL, 0);
                wchar_t *wHtml = malloc((wLen + 1) * sizeof(wchar_t));
                MultiByteToWideChar(CP_UTF8, 0, htmlUtf8, (int)htmlSize, wHtml, wLen);
                wHtml[wLen] = L'\0';
                webview->lpVtbl->NavigateToString(webview, wHtml);
                free(wHtml);
            }
        }
    }

    return S_OK;
}

// --- WebMessageReceivedHandler ---

static HRESULT STDMETHODCALLTYPE MsgReceived_Invoke(ICoreWebView2WebMessageReceivedEventHandler *This, ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args) {
    (void)This; (void)sender;

    LPWSTR wMsg = NULL;
    args->lpVtbl->TryGetWebMessageAsString(args, &wMsg);
    if (!wMsg) return S_OK;

    // Convert wide to UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, wMsg, -1, NULL, 0, NULL, NULL);
    char *msg = malloc(len);
    WideCharToMultiByte(CP_UTF8, 0, wMsg, -1, msg, len, NULL, NULL);
    CoTaskMemFree(wMsg);

    // Parse action
    char action[64] = {0};
    json_get_string(msg, "action", action, sizeof(action));

    if (strcmp(action, "getSettings") == 0) {
        load_settings();
        webview_push_settings();
    } else if (strcmp(action, "getServiceState") == 0) {
        webview_push_service_state();
    } else if (strcmp(action, "saveSettings") == 0) {
        char ip[64] = {0};
        int port = 0;
        BOOL enHTTP = TRUE, enMonOff = TRUE;
        json_get_string(msg, "bindIP", ip, sizeof(ip));
        json_get_int(msg, "bindPort", &port);
        json_get_bool(msg, "enableHTTP", &enHTTP);
        json_get_bool(msg, "enableMonitorOff", &enMonOff);

        // Validate IP
        struct in_addr tmpAddr;
        if (inet_pton(AF_INET, ip, &tmpAddr) != 1) {
            webview_push_action_result("saveSettings", FALSE);
            free(msg);
            return S_OK;
        }
        if (port < 1 || port > 65535) {
            webview_push_action_result("saveSettings", FALSE);
            free(msg);
            return S_OK;
        }

        BOOL wasRunning = (query_service_state() == 2);
        BOOL ok = save_settings(ip, (DWORD)port, enHTTP ? 1 : 0, enMonOff ? 1 : 0);
        webview_push_action_result("saveSettings", ok);

        if (ok && wasRunning) {
            restart_service();
            Sleep(500);
        }
    } else if (strcmp(action, "install") == 0) {
        BOOL ok = install_service();
        webview_push_action_result("install", ok);
    } else if (strcmp(action, "uninstall") == 0) {
        BOOL ok = uninstall_service();
        webview_push_action_result("uninstall", ok);
    } else if (strcmp(action, "start") == 0) {
        BOOL ok = start_service();
        Sleep(500);
        webview_push_action_result("start", ok);
    } else if (strcmp(action, "stop") == 0) {
        BOOL ok = stop_service();
        Sleep(500);
        webview_push_action_result("stop", ok);
    } else if (strcmp(action, "restart") == 0) {
        BOOL ok = restart_service();
        Sleep(500);
        webview_push_action_result("restart", ok);
    } else if (strcmp(action, "resize") == 0) {
        int contentHeight = 0;
        json_get_int(msg, "height", &contentHeight);
        if (contentHeight > 0 && g_hWnd) {
            // Convert desired client height to window height (accounts for title bar, borders)
            RECT clientRect = {0}, windowRect = {0};
            GetClientRect(g_hWnd, &clientRect);
            GetWindowRect(g_hWnd, &windowRect);
            int chromeH = (windowRect.bottom - windowRect.top) - (clientRect.bottom - clientRect.top);
            int newWindowH = contentHeight + chromeH;
            int windowW = windowRect.right - windowRect.left;
            // Keep the window centered horizontally on its current position
            SetWindowPos(g_hWnd, NULL, 0, 0, windowW, newWindowH,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    free(msg);
    return S_OK;
}

// ============================================================================
// WebView2 config window
// ============================================================================

static LRESULT CALLBACK WebViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            if (g_webviewController) {
                RECT bounds;
                GetClientRect(hwnd, &bounds);
                g_webviewController->lpVtbl->put_Bounds(g_webviewController, bounds);
            }
            return 0;

        case WM_CLOSE:
            if (g_webviewController) {
                g_webviewController->lpVtbl->Close(g_webviewController);
                g_webviewController->lpVtbl->Release(g_webviewController);
                g_webviewController = NULL;
            }
            if (g_webviewView) {
                g_webviewView->lpVtbl->Release(g_webviewView);
                g_webviewView = NULL;
            }
            if (g_webviewEnv) {
                g_webviewEnv->lpVtbl->Release(g_webviewEnv);
                g_webviewEnv = NULL;
            }
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void show_webview_config(void) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    if (!load_webview2_loader()) {
        MessageBoxW(NULL,
            L"WebView2Loader.dll not found.\n\n"
            L"Please ensure WebView2Loader.dll is in the same directory as LockService.exe.",
            L"LockService", MB_ICONERROR | MB_OK);
        CoUninitialize();
        return;
    }

    // Register window class
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WebViewWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hIcon = LoadIconW(GetModuleHandle(NULL), MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"LockServiceConfigWnd";
    wc.hIconSm = LoadIconW(GetModuleHandle(NULL), MAKEINTRESOURCEW(IDI_APP_ICON));
    RegisterClassExW(&wc);

    // Create window centered on screen
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winW = 480, winH = 420;
    int posX = (screenW - winW) / 2;
    int posY = (screenH - winH) / 2;

    g_hWnd = CreateWindowExW(0, L"LockServiceConfigWnd", L"Lock Service Configuration",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        posX, posY, winW, winH,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    if (!g_hWnd) {
        MessageBoxW(NULL, L"Failed to create window.", L"LockService", MB_ICONERROR);
        CoUninitialize();
        return;
    }

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    // Build user data folder path in %TEMP%
    WCHAR userDataFolder[MAX_PATH];
    DWORD tempLen = GetTempPathW(MAX_PATH, userDataFolder);
    if (tempLen > 0 && tempLen < MAX_PATH - 20) {
        wcscat(userDataFolder, L"LockService.WebView2");
    } else {
        wcscpy(userDataFolder, L"");
    }

    // Create environment
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *envHandler = malloc(sizeof(*envHandler));
    envHandler->lpVtbl = &g_envCompletedVtbl;
    envHandler->refCount = 1;

    HRESULT hr = fnCreateEnvironment(NULL, userDataFolder[0] ? userDataFolder : NULL, NULL, envHandler);
    envHandler->lpVtbl->Release(envHandler);

    if (FAILED(hr)) {
        MessageBoxW(NULL,
            L"Failed to initialize WebView2.\n\n"
            L"Please ensure the Microsoft Edge WebView2 Runtime is installed.\n"
            L"Download from: https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
            L"LockService", MB_ICONERROR | MB_OK);
        DestroyWindow(g_hWnd);
        CoUninitialize();
        return;
    }

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
}

// Main entry point
int main(int argc, char* argv[]) {
    // Validate argc before accessing argv
    if (argc < 1) {
        fprintf(stderr, "Invalid command line\n");
        return 1;
    }
    
    if (argc > 1 && strcmp(argv[1], HELP_FLAG) == 0) {
        run_helper();
        return 0;
    }
    
    if (argc > 1 && strcmp(argv[1], KEYBOARD_HOOK_FLAG) == 0) {
        run_keyboard_hook_helper();
        return 0;
    }
    
    if (argc > 1) {
        // Reattach to parent console so printf/fprintf output is visible
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
        }
        if (strcmp(argv[1], "install") == 0) {
            return install_service() ? 0 : 1;
        } else if (strcmp(argv[1], "uninstall") == 0) {
            return uninstall_service() ? 0 : 1;
        } else {
            fprintf(stderr, "Unknown command: %s\n", argv[1]);
            fprintf(stderr, "Usage: %s [install|uninstall]\n", argv[0]);
            return 1;
        }
    }
    
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        {L"LockService", service_main},
        {NULL, NULL}
    };
    
    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            if (!IsUserAnAdmin()) {
                MessageBoxW(NULL,
                    L"This program must be run as Administrator to configure the service.",
                    L"LockService", MB_ICONWARNING | MB_OK);
                return 1;
            }
            show_webview_config();
            return 0;
        }
        fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
        fprintf(stderr, "This program must be run as a Windows Service\n");
        return 1;
    }
    
    return 0;
}

