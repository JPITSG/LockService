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

// Dialog control IDs
#define IDC_STATUS_LABEL 101
#define IDC_BTN_INSTALL  102
#define IDC_BTN_UNINSTALL 103
#define IDC_BTN_START    104
#define IDC_BTN_STOP     105
#define IDC_LBL_BIND_IP   106
#define IDC_EDIT_BIND_IP   107
#define IDC_LBL_BIND_PORT  108
#define IDC_EDIT_BIND_PORT 109
#define IDC_BTN_SAVE       110
#define IDC_BTN_RESTART    111
#define IDC_SEPARATOR      112
#define IDC_STATUS_STATE   113

// Registry settings
#define REG_KEY_PATH       "SOFTWARE\\JPIT\\LockService"
#define REG_VALUE_BIND_IP  "BindIP"
#define REG_VALUE_BIND_PORT "BindPort"

#ifndef SS_ETCHEDHORZ
#define SS_ETCHEDHORZ 0x00000010
#endif

// Settings globals
static char g_bindIP[64] = "0.0.0.0";
static DWORD g_bindPort = 8888;

// Service state for colored status tracking
static int g_lastServiceState = -1;

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
							Sleep(500);
                            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
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
		Sleep(500);
        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
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
					Sleep(500);
                    SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
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
    
    if (!LockWorkStation()) {
        if (g_hEventLog) {
            log_error("LockWorkStation failed: %lu", GetLastError());
            DeregisterEventSource(g_hEventLog);
        }
        exit(1);
    }
	Sleep(500);
    SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
    
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

        RegCloseKey(hKey);
    }
}

// Save bind settings to registry
static BOOL save_settings(const char* ip, DWORD port) {
    HKEY hKey;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, NULL, 0, KEY_WRITE, NULL, &hKey, &disp) != ERROR_SUCCESS)
        return FALSE;

    BOOL ok = TRUE;
    if (RegSetValueExA(hKey, REG_VALUE_BIND_IP, 0, REG_SZ, (const BYTE*)ip, (DWORD)strlen(ip) + 1) != ERROR_SUCCESS)
        ok = FALSE;
    if (RegSetValueExA(hKey, REG_VALUE_BIND_PORT, 0, REG_DWORD, (const BYTE*)&port, sizeof(port)) != ERROR_SUCCESS)
        ok = FALSE;

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

    // Start HTTP server thread
    HANDLE hHttpThread = CreateThread(NULL, 0, http_server_thread, NULL, 0, NULL);
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
    
    // Start session monitoring thread (does immediate check, then every 10 seconds)
    HANDLE hMonitorThread = CreateThread(NULL, 0, session_monitor_thread, NULL, 0, NULL);
    if (!hMonitorThread) {
        DWORD dwError = GetLastError();
        log_error("Failed to create session monitor thread: %lu", dwError);
        SetEvent(g_ServiceStopEvent);
        WaitForSingleObject(hHttpThread, THREAD_SHUTDOWN_TIMEOUT_MS);
        CloseHandle(hHttpThread);
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

// Stop the service via SCM
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
    return bResult;
}

// Restart the service (stop then start)
static BOOL restart_service(void) {
    stop_service();
    Sleep(500);
    return start_service();
}

// Helper to add a control to dialog template
static BYTE* AddDialogControl(BYTE* ptr, WORD ctrlId, WORD classAtom, DWORD style,
                               short posX, short posY, short width, short height,
                               const wchar_t* text) {
    // Align to DWORD
    ptr = (BYTE*)(((ULONG_PTR)ptr + 3) & ~3);

    DLGITEMTEMPLATE* item = (DLGITEMTEMPLATE*)ptr;
    item->style = style;
    item->dwExtendedStyle = 0;
    item->x = posX;
    item->y = posY;
    item->cx = width;
    item->cy = height;
    item->id = ctrlId;
    ptr += sizeof(DLGITEMTEMPLATE);

    // Class (atom)
    *(WORD*)ptr = 0xFFFF;
    ptr += sizeof(WORD);
    *(WORD*)ptr = classAtom;
    ptr += sizeof(WORD);

    // Text
    size_t textLen = wcslen(text) + 1;
    memcpy(ptr, text, textLen * sizeof(wchar_t));
    ptr += textLen * sizeof(wchar_t);

    // Creation data (none)
    *(WORD*)ptr = 0;
    ptr += sizeof(WORD);

    return ptr;
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

// Update button enable states based on current service state
static void RefreshButtonStates(HWND hDlg) {
    int state = query_service_state();
    g_lastServiceState = state;
    const wchar_t* prefixText;
    const wchar_t* stateText;

    switch (state) {
        case 0: prefixText = L"Status: Not Installed"; stateText = L""; break;
        case 1: prefixText = L"Status: Installed "; stateText = L"(Stopped)"; break;
        case 2: prefixText = L"Status: Installed "; stateText = L"(Running)"; break;
        case 3: prefixText = L"Status: Installed "; stateText = L"(Transitioning...)"; break;
        default: prefixText = L"Status: Unknown"; stateText = L""; break;
    }

    SetDlgItemTextW(hDlg, IDC_STATUS_LABEL, prefixText);
    SetDlgItemTextW(hDlg, IDC_STATUS_STATE, stateText);

    // Measure prefix width and reposition state label right after it
    HDC hdc = GetDC(hDlg);
    HFONT hFont = (HFONT)SendDlgItemMessage(hDlg, IDC_STATUS_LABEL, WM_GETFONT, 0, 0);
    HGDIOBJ hOld = NULL;
    if (hFont) hOld = SelectObject(hdc, hFont);
    SIZE sz;
    GetTextExtentPoint32W(hdc, prefixText, (int)wcslen(prefixText), &sz);
    if (hOld) SelectObject(hdc, hOld);
    ReleaseDC(hDlg, hdc);

    RECT rc;
    GetWindowRect(GetDlgItem(hDlg, IDC_STATUS_LABEL), &rc);
    MapWindowPoints(NULL, hDlg, (POINT*)&rc, 2);
    SetWindowPos(GetDlgItem(hDlg, IDC_STATUS_STATE), NULL,
        rc.left + sz.cx, rc.top, rc.right - rc.left - sz.cx, rc.bottom - rc.top,
        SWP_NOZORDER | SWP_NOACTIVATE);
    InvalidateRect(GetDlgItem(hDlg, IDC_STATUS_STATE), NULL, TRUE);

    BOOL installed = (state > 0);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_INSTALL),   !installed);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_UNINSTALL),  installed);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_RESTART),    installed && state == 2);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_START),      installed && state == 1);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_STOP),       installed && state == 2);
}

// Configuration dialog procedure
static INT_PTR CALLBACK ConfigDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static char origIP[64];
    static DWORD origPort;

    switch (msg) {
        case WM_INITDIALOG:
            load_settings();
            SetDlgItemTextA(hDlg, IDC_EDIT_BIND_IP, g_bindIP);
            SetDlgItemInt(hDlg, IDC_EDIT_BIND_PORT, g_bindPort, FALSE);
            strncpy(origIP, g_bindIP, sizeof(origIP));
            origIP[sizeof(origIP) - 1] = '\0';
            origPort = g_bindPort;
            EnableWindow(GetDlgItem(hDlg, IDC_BTN_SAVE), FALSE);
            RefreshButtonStates(hDlg);
            return TRUE;

        case WM_COMMAND:
            // Dirty tracking for edit controls
            if (HIWORD(wParam) == EN_CHANGE &&
                (LOWORD(wParam) == IDC_EDIT_BIND_IP || LOWORD(wParam) == IDC_EDIT_BIND_PORT)) {
                char curIP[64] = {0};
                GetDlgItemTextA(hDlg, IDC_EDIT_BIND_IP, curIP, sizeof(curIP));
                DWORD curPort = GetDlgItemInt(hDlg, IDC_EDIT_BIND_PORT, NULL, FALSE);
                BOOL dirty = (strcmp(curIP, origIP) != 0 || curPort != origPort);
                EnableWindow(GetDlgItem(hDlg, IDC_BTN_SAVE), dirty);
                return TRUE;
            }

            switch (LOWORD(wParam)) {
                case IDC_BTN_SAVE: {
                    char ip[64] = {0};
                    GetDlgItemTextA(hDlg, IDC_EDIT_BIND_IP, ip, sizeof(ip));

                    // Validate IP
                    struct in_addr tmpAddr;
                    if (inet_pton(AF_INET, ip, &tmpAddr) != 1) {
                        MessageBoxW(hDlg, L"Invalid IP address.", L"Validation Error", MB_ICONERROR);
                        SetFocus(GetDlgItem(hDlg, IDC_EDIT_BIND_IP));
                        return TRUE;
                    }

                    // Validate port
                    BOOL translated = FALSE;
                    UINT port = GetDlgItemInt(hDlg, IDC_EDIT_BIND_PORT, &translated, FALSE);
                    if (!translated || port < 1 || port > 65535) {
                        MessageBoxW(hDlg, L"Port must be between 1 and 65535.", L"Validation Error", MB_ICONERROR);
                        SetFocus(GetDlgItem(hDlg, IDC_EDIT_BIND_PORT));
                        return TRUE;
                    }

                    if (!save_settings(ip, (DWORD)port)) {
                        MessageBoxW(hDlg, L"Failed to save settings to registry.", L"Error", MB_ICONERROR);
                        return TRUE;
                    }

                    // Update originals and disable Save
                    strncpy(origIP, ip, sizeof(origIP));
                    origIP[sizeof(origIP) - 1] = '\0';
                    origPort = (DWORD)port;
                    EnableWindow(GetDlgItem(hDlg, IDC_BTN_SAVE), FALSE);

                    // Restart service if running
                    if (g_lastServiceState == 2) {
                        restart_service();
                        Sleep(500);
                    }

                    RefreshButtonStates(hDlg);
                    return TRUE;
                }

                case IDC_BTN_RESTART:
                    restart_service();
                    Sleep(500);
                    RefreshButtonStates(hDlg);
                    return TRUE;

                case IDC_BTN_INSTALL:
                    if (!install_service())
                        MessageBoxW(hDlg, L"Failed to install service.", L"Error", MB_ICONERROR);
                    RefreshButtonStates(hDlg);
                    return TRUE;

                case IDC_BTN_UNINSTALL:
                    if (!uninstall_service())
                        MessageBoxW(hDlg, L"Failed to uninstall service.", L"Error", MB_ICONERROR);
                    RefreshButtonStates(hDlg);
                    return TRUE;

                case IDC_BTN_START:
                    if (!start_service())
                        MessageBoxW(hDlg, L"Failed to start service.", L"Error", MB_ICONERROR);
                    Sleep(500);
                    RefreshButtonStates(hDlg);
                    return TRUE;

                case IDC_BTN_STOP:
                    if (!stop_service())
                        MessageBoxW(hDlg, L"Failed to stop service.", L"Error", MB_ICONERROR);
                    Sleep(500);
                    RefreshButtonStates(hDlg);
                    return TRUE;
            }
            break;

        case WM_CTLCOLORSTATIC:
            if ((HWND)lParam == GetDlgItem(hDlg, IDC_STATUS_STATE)) {
                HDC hdc = (HDC)wParam;
                if (g_lastServiceState == 2)
                    SetTextColor(hdc, RGB(0, 128, 0));
                else if (g_lastServiceState == 1)
                    SetTextColor(hdc, RGB(192, 0, 0));
                SetBkMode(hdc, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
            }
            break;

        case WM_CLOSE:
            EndDialog(hDlg, 0);
            return TRUE;
    }
    return FALSE;
}

// Build and show the configuration dialog
static void show_config_dialog(void) {
    BYTE buf[4096];
    memset(buf, 0, sizeof(buf));
    BYTE* ptr = buf;

    // Dialog template header
    DLGTEMPLATE* dlg = (DLGTEMPLATE*)ptr;
    dlg->style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_SETFONT | DS_CENTER;
    dlg->dwExtendedStyle = 0;
    dlg->cdit = 13;  // 2 status + 2 labels + 2 edits + 1 save + 1 separator + 5 buttons
    dlg->x = 0;
    dlg->y = 0;
    dlg->cx = 254;
    dlg->cy = 138;
    ptr += sizeof(DLGTEMPLATE);

    // Menu (none)
    *(WORD*)ptr = 0;
    ptr += sizeof(WORD);

    // Class (default)
    *(WORD*)ptr = 0;
    ptr += sizeof(WORD);

    // Title
    const wchar_t* title = L"LockService Configuration";
    size_t titleLen = wcslen(title) + 1;
    memcpy(ptr, title, titleLen * sizeof(wchar_t));
    ptr += titleLen * sizeof(wchar_t);

    // Font (DS_SETFONT): size + name
    *(WORD*)ptr = 8;
    ptr += sizeof(WORD);
    const wchar_t* font = L"Segoe UI";
    size_t fontLen = wcslen(font) + 1;
    memcpy(ptr, font, fontLen * sizeof(wchar_t));
    ptr += fontLen * sizeof(wchar_t);

    short margin = 14;
    short contentW = 226;
    short lblW = 42;
    short editX = margin + lblW + 2;
    short editW = contentW - lblW - 2;
    short btnW = 42, btnH = 16, gap = 4;

    // 1a. Status prefix label (y=14, h=12)
    ptr = AddDialogControl(ptr, IDC_STATUS_LABEL, 0x0082,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, 14, contentW, 12, L"Status: Checking...");

    // 1b. Status state label — colored, repositioned dynamically
    ptr = AddDialogControl(ptr, IDC_STATUS_STATE, 0x0082,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, 14, contentW, 12, L"");

    // 2. Bind IP label (y=38 for vertical centering with 14-tall edit at y=36)
    ptr = AddDialogControl(ptr, IDC_LBL_BIND_IP, 0x0082,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, 38, lblW, 12, L"Bind IP:");

    // 3. Bind IP edit (y=36, h=14)
    ptr = AddDialogControl(ptr, IDC_EDIT_BIND_IP, 0x0081,
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
        editX, 36, editW, 14, L"");

    // 4. Bind Port label (y=58 for vertical centering with 14-tall edit at y=56)
    ptr = AddDialogControl(ptr, IDC_LBL_BIND_PORT, 0x0082,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        margin, 58, lblW, 12, L"Bind Port:");

    // 5. Bind Port edit (y=56, h=14) — ES_NUMBER for digits only
    ptr = AddDialogControl(ptr, IDC_EDIT_BIND_PORT, 0x0081,
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER,
        editX, 56, 50, 14, L"");

    // 6. Save button (y=78, h=16) — right-aligned
    ptr = AddDialogControl(ptr, IDC_BTN_SAVE, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin + contentW - btnW, 78, btnW, btnH, L"Save");

    // 7. Etched horizontal separator (y=100, h=2)
    ptr = AddDialogControl(ptr, IDC_SEPARATOR, 0x0082,
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        0, 100, 254, 2, L"");

    // 8-12. Bottom buttons (y=108, h=16): Install, Uninstall, Restart, Start, Stop
    ptr = AddDialogControl(ptr, IDC_BTN_INSTALL, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin, 108, btnW, btnH, L"Install");

    ptr = AddDialogControl(ptr, IDC_BTN_UNINSTALL, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin + (btnW + gap), 108, btnW, btnH, L"Uninstall");

    ptr = AddDialogControl(ptr, IDC_BTN_RESTART, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin + 2 * (btnW + gap), 108, btnW, btnH, L"Restart");

    ptr = AddDialogControl(ptr, IDC_BTN_START, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin + 3 * (btnW + gap), 108, btnW, btnH, L"Start");

    ptr = AddDialogControl(ptr, IDC_BTN_STOP, 0x0080,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        margin + 4 * (btnW + gap), 108, btnW, btnH, L"Stop");

    DialogBoxIndirectParamW(GetModuleHandle(NULL), (DLGTEMPLATE*)buf, NULL, ConfigDialogProc, 0);
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
            show_config_dialog();
            return 0;
        }
        fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
        fprintf(stderr, "This program must be run as a Windows Service\n");
        return 1;
    }
    
    return 0;
}

