import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:share_plus/share_plus.dart' as share_plus;
import 'package:permission_handler/permission_handler.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart' as secure_storage;
import 'package:crypto/crypto.dart';

WebViewEnvironment? webViewEnvironment;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final isMobile = !kIsWeb && (defaultTargetPlatform == TargetPlatform.android || defaultTargetPlatform == TargetPlatform.iOS);

  if (isMobile) {
    try {
      SystemChrome.setPreferredOrientations([
        DeviceOrientation.portraitUp,
        DeviceOrientation.portraitDown,
        DeviceOrientation.landscapeLeft,
        DeviceOrientation.landscapeRight,
      ]);
    } catch (_) {}
  } else if (!kIsWeb && defaultTargetPlatform == TargetPlatform.windows) {
    try {
      final availableVersion = await WebViewEnvironment.getAvailableVersion();
      if (availableVersion != null) {
        final appData = Platform.environment['LOCALAPPDATA'] ?? Directory.systemTemp.path;
        final userDataDir = Directory('$appData\\swab_webview_data');
        if (!userDataDir.existsSync()) {
          userDataDir.createSync(recursive: true);
        }
        webViewEnvironment = await WebViewEnvironment.create(
          settings: WebViewEnvironmentSettings(userDataFolder: userDataDir.path),
        );
      }
    } catch (e) {
      debugPrint('WebViewEnvironment init error: $e');
    }
  }

  runApp(const MyApp());
}

/// ================= Clipboard Channel =================
class ClipboardChannel {
  static Future<void> copyText(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
  }

  static Future<String> pasteText() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    return data?.text ?? '';
  }
}
/// ====================================================

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '{{APP_NAME}}',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      themeMode: ThemeMode.system,
      home: const WebViewScreen(),
    );
  }
}

class WebViewScreen extends StatefulWidget {
  const WebViewScreen({super.key});

  @override
  State<WebViewScreen> createState() => _WebViewScreenState();
}

class _WebViewScreenState extends State<WebViewScreen> with WidgetsBindingObserver {
  InAppWebViewController? webViewController;
  PullToRefreshController? pullToRefreshController;
  double progress = 0;
  String url = '{{APP_URL}}';
  bool isLoading = true;
  bool isOffline = false;
  bool canGoBack = false;
  bool canGoForward = false;
  bool isUserLoggedIn = false;
  bool isWebView2Missing = false;
  int _webViewKey = 0;
  bool _wasOffline = false;
  StreamSubscription<List<ConnectivityResult>>? _connectivitySubscription;
  Timer? _watchdogTimer;

  bool get isMobile => !kIsWeb && (defaultTargetPlatform == TargetPlatform.android || defaultTargetPlatform == TargetPlatform.iOS);

  static const bool ALLOW_ZOOM = false;
  static const bool ENABLE_JAVASCRIPT = false;
  static const bool ENABLE_DOM_STORAGE = false;
  static const bool ENABLE_GEOLOCATION = false;
  static const bool ENABLE_PULL_TO_REFRESH = false;
  static const bool SHOW_NAVIGATION_BAR = false;
  static const bool SHOW_NAVIGATION_BAR_2 = false;
  static const bool ENABLE_FILE_ACCESS = false;
  static const bool ENABLE_CACHE = false;
  static const bool ENABLE_MEDIA_AUTOPLAY = false;
  static const bool ENABLE_CAMERA = false;
  static const bool ENABLE_MICROPHONE = false;
  static const bool ENABLE_SSL_PINNING = false;
  static const String SSL_PINS = '';
  static const bool ENABLE_BIOMETRIC_AUTH = false;
  static const bool ENABLE_APP_LOCK = false;
  static const String APP_LOCK_PIN = '';
  static const bool ENABLE_SECURE_STORAGE = false;

  // Splash Screen Configuration
  static const bool ENABLE_SPLASH_SCREEN = false;
  static const String SPLASH_TITLE = '{{APP_NAME}}';
  static const String SPLASH_SUBTITLE = '';
  static const String SPLASH_BG_COLOR = '#FFFFFF';
  static const String SPLASH_TEXT_COLOR = '#1E293B';
  static const int SPLASH_DURATION_SECONDS = 2;
  static const bool HAS_CUSTOM_SPLASH_IMAGE = false;

  // Error / Offline Page Configuration
  static const bool ENABLE_ERROR_PAGE = false;
  static const String ERROR_TITLE = 'No Internet Connection';
  static const String ERROR_MESSAGE = 'Please check your connection and try again';
  static const String ERROR_BUTTON_TEXT = 'Retry';
  static const String ERROR_BG_COLOR = '#FFFFFF';
  static const String ERROR_TEXT_COLOR = '#334155';
  static const bool HAS_CUSTOM_ERROR_IMAGE = false;

  final secure_storage.FlutterSecureStorage _secureStorage = const secure_storage.FlutterSecureStorage(
    aOptions: secure_storage.AndroidOptions(encryptedSharedPreferences: true),
    iOptions: secure_storage.IOSOptions(accessibility: secure_storage.KeychainAccessibility.first_unlock),
  );

  bool _isLocked = ENABLE_BIOMETRIC_AUTH || ENABLE_APP_LOCK;
  bool _isAuthenticating = false;
  String _enteredPin = '';
  String _pinErrorMessage = '';
  bool _showSplash = ENABLE_SPLASH_SCREEN;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _startWatchdog();
    if (ENABLE_SPLASH_SCREEN) {
      Future.delayed(const Duration(seconds: SPLASH_DURATION_SECONDS), () {
        if (mounted && _showSplash) {
          setState(() {
            _showSplash = false;
          });
        }
      });
    }
    if (_isLocked && ENABLE_BIOMETRIC_AUTH) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _authenticateWithBiometrics();
      });
    }
    var rawUrl = url.trim();
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
      rawUrl = 'https://$rawUrl';
    }
    url = rawUrl;
    _checkConnectivity();
    if (!kIsWeb && defaultTargetPlatform == TargetPlatform.windows) {
      WebViewEnvironment.getAvailableVersion().then((version) {
        if (version == null && mounted) {
          setState(() {
            isWebView2Missing = true;
          });
        }
      });
    }
    pullToRefreshController = (ENABLE_PULL_TO_REFRESH && isMobile)
        ? PullToRefreshController(
            settings: PullToRefreshSettings(color: Colors.blue),
            onRefresh: () async {
              webViewController?.reload();
            },
          )
        : null;
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _connectivitySubscription?.cancel();
    _watchdogTimer?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    if (state == AppLifecycleState.resumed) {
      try {
        if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
          webViewController?.resume();
          webViewController?.resumeTimers();
        }
      } catch (e) {
        debugPrint('WebView resume error: $e');
      }

      _checkAndRecoverIfFrozen();

      if ((ENABLE_BIOMETRIC_AUTH || ENABLE_APP_LOCK) && !_isAuthenticating) {
        setState(() {
          _isLocked = true;
          _enteredPin = '';
          _pinErrorMessage = '';
        });
        if (ENABLE_BIOMETRIC_AUTH) {
          _authenticateWithBiometrics();
        }
      }
    } else if (state == AppLifecycleState.paused || state == AppLifecycleState.inactive) {
      try {
        if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
          webViewController?.pause();
          webViewController?.pauseTimers();
        }
      } catch (e) {
        debugPrint('WebView pause error: $e');
      }
    }
  }

  void _recreateWebView() {
    if (!mounted) return;
    setState(() {
      _webViewKey++;
      isLoading = true;
      progress = 0;
    });
  }

  Future<void> _checkAndRecoverIfFrozen() async {
    if (webViewController == null || _isLocked || _showSplash || isOffline) return;
    try {
      final res = await webViewController!
          .evaluateJavascript(source: '1 + 1')
          .timeout(const Duration(milliseconds: 2500));
      if (res != 2 && res != '2') {
        debugPrint('WebView ping failed with unexpected return ($res). Reviving...');
        _recreateWebView();
      }
    } catch (e) {
      debugPrint('WebView was unresponsive or timed out after wake ($e). Reviving...');
      _recreateWebView();
    }
  }

  void _startWatchdog() {
    _watchdogTimer?.cancel();
    _watchdogTimer = Timer.periodic(const Duration(minutes: 3), (_) {
      if (mounted && !_isLocked && !_showSplash && !isOffline) {
        _checkAndRecoverIfFrozen();
      }
    });
  }

  Future<void> _authenticateWithBiometrics() async {
    if (_isAuthenticating) return;
    _isAuthenticating = true;
    try {
      final auth = LocalAuthentication();
      final canCheck = await auth.canCheckBiometrics;
      final isSupported = await auth.isDeviceSupported();
      if (canCheck || isSupported) {
        final didAuth = await auth.authenticate(
          localizedReason: 'Authenticate to access {{APP_NAME}}',
          options: const AuthenticationOptions(
            biometricOnly: false,
            stickyAuth: true,
          ),
        );
        if (didAuth && mounted) {
          setState(() {
            _isLocked = false;
            _enteredPin = '';
            _pinErrorMessage = '';
          });
        }
      }
    } catch (e) {
      debugPrint('Biometric auth error: $e');
    } finally {
      _isAuthenticating = false;
    }
  }

  void _onDigitPressed(String digit) {
    final targetPin = APP_LOCK_PIN.trim();
    final maxLen = targetPin.isNotEmpty ? targetPin.length : 6;
    if (_enteredPin.length >= maxLen) return;

    setState(() {
      _enteredPin += digit;
      _pinErrorMessage = '';
    });

    if (targetPin.isNotEmpty && _enteredPin.length == targetPin.length) {
      if (_enteredPin == targetPin) {
        setState(() {
          _isLocked = false;
          _enteredPin = '';
          _pinErrorMessage = '';
        });
      } else {
        setState(() {
          _pinErrorMessage = 'Incorrect PIN. Please try again.';
          _enteredPin = '';
        });
      }
    }
  }

  void _onDeletePressed() {
    if (_enteredPin.isNotEmpty) {
      setState(() {
        _enteredPin = _enteredPin.substring(0, _enteredPin.length - 1);
        _pinErrorMessage = '';
      });
    }
  }

  Future<void> _checkConnectivity() async {
    try {
      final connectivityResult = await Connectivity().checkConnectivity();
      final nowOffline = connectivityResult.contains(ConnectivityResult.none);
      if (mounted) {
        setState(() {
          isOffline = nowOffline;
          _wasOffline = nowOffline;
        });
      }

      _connectivitySubscription?.cancel();
      _connectivitySubscription = Connectivity().onConnectivityChanged.listen((result) {
        if (mounted) {
          final nowOffline = result.contains(ConnectivityResult.none);
          final transitionedToOnline = _wasOffline && !nowOffline;
          setState(() {
            isOffline = nowOffline;
            _wasOffline = nowOffline;
          });
          // ONLY reload if the app was previously offline and connection is now restored!
          if (transitionedToOnline) {
            debugPrint('Connection restored from offline, reloading WebView...');
            webViewController?.reload();
          }
        }
      });
    } catch (e) {
      debugPrint('Connectivity check warning: $e');
    }
  }

  Future<void> _updateNavigationState() async {
    final canBack = await webViewController?.canGoBack() ?? false;
    final canForward = await webViewController?.canGoForward() ?? false;
    bool loggedIn = false;
    try {
      final res = await webViewController?.evaluateJavascript(source: r'''
(function() {
  if (typeof window.__iewn_check_logged_in === 'function') {
    return window.__iewn_check_logged_in();
  }
  return false;
})();
''');
      if (res != null) {
        if (res is bool) {
          loggedIn = res;
        } else if (res is String) {
          loggedIn = res.toLowerCase() == 'true';
        }
      }
    } catch (e) {
      debugPrint('Auth check error in _updateNavigationState: $e');
    }

    if (mounted) {
      setState(() {
        canGoBack = canBack;
        canGoForward = canForward;
        isUserLoggedIn = loggedIn;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !_isLocked && !canGoBack,
      onPopInvokedWithResult: (didPop, result) async {
        if (!didPop && canGoBack && !_isLocked) {
          webViewController?.goBack();
        }
      },
      child: Scaffold(
        body: SafeArea(
          child: Stack(
            children: [
              if (isWebView2Missing)
                _buildWebView2MissingWidget()
              else
                InAppWebView(
                  key: ValueKey(_webViewKey),
                  webViewEnvironment: webViewEnvironment,
                  initialUrlRequest: URLRequest(url: WebUri(url)),
                  initialSettings: InAppWebViewSettings(
                    useShouldOverrideUrlLoading: true,
                    mediaPlaybackRequiresUserGesture: !ENABLE_MEDIA_AUTOPLAY,
                    javaScriptEnabled: ENABLE_JAVASCRIPT,
                    domStorageEnabled: ENABLE_DOM_STORAGE,
                    databaseEnabled: ENABLE_DOM_STORAGE,
                    clearCache: !ENABLE_CACHE,
                    cacheEnabled: ENABLE_CACHE,
                    supportZoom: ALLOW_ZOOM,
                    allowFileAccess: ENABLE_FILE_ACCESS,
                    allowContentAccess: ENABLE_FILE_ACCESS,
                    geolocationEnabled: ENABLE_GEOLOCATION,
                    allowsInlineMediaPlayback: true,
                    useHybridComposition: false,
                    useOnRenderProcessGone: true,
                    hardwareAcceleration: true,
                    mixedContentMode: MixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW,
                    safeBrowsingEnabled: false,
                    disableDefaultErrorPage: true,
                    cacheMode: ENABLE_CACHE ? CacheMode.LOAD_DEFAULT : CacheMode.LOAD_NO_CACHE,
                  ),
                  pullToRefreshController: isMobile ? pullToRefreshController : null,
                  onRenderProcessGone: (controller, detail) async {
                    debugPrint('WebView render process gone (didCrash: ${detail.didCrash}). Reviving...');
                    _recreateWebView();
                  },
                  onWebContentProcessDidTerminate: (controller) async {
                    debugPrint('WebView content process terminated. Reviving...');
                    _recreateWebView();
                  },
                  onPermissionRequest: (controller, request) async {
                    final grantedResources = <PermissionResourceType>[];

                    for (final resource in request.resources) {
                      if (resource == PermissionResourceType.CAMERA) {
                        if (ENABLE_CAMERA) {
                          if (isMobile) {
                            try {
                              final status = await Permission.camera.request();
                              if (status.isGranted) {
                                grantedResources.add(resource);
                              }
                            } catch (e) {
                              debugPrint('Camera permission request error: $e');
                              grantedResources.add(resource);
                            }
                          } else {
                            grantedResources.add(resource);
                          }
                        }
                      } else if (resource == PermissionResourceType.MICROPHONE) {
                        if (ENABLE_MICROPHONE) {
                          if (isMobile) {
                            try {
                              final status = await Permission.microphone.request();
                              if (status.isGranted) {
                                grantedResources.add(resource);
                              }
                            } catch (e) {
                              debugPrint('Microphone permission request error: $e');
                              grantedResources.add(resource);
                            }
                          } else {
                            grantedResources.add(resource);
                          }
                        }
                      } else if (resource == PermissionResourceType.CAMERA_AND_MICROPHONE) {
                        if (ENABLE_CAMERA && ENABLE_MICROPHONE) {
                          if (isMobile) {
                            try {
                              final camStatus = await Permission.camera.request();
                              final micStatus = await Permission.microphone.request();
                              if (camStatus.isGranted && micStatus.isGranted) {
                                grantedResources.add(resource);
                              }
                            } catch (e) {
                              debugPrint('Camera/Microphone permission request error: $e');
                              grantedResources.add(resource);
                            }
                          } else {
                            grantedResources.add(resource);
                          }
                        }
                      } else {
                        grantedResources.add(resource);
                      }
                    }

                    if (grantedResources.isNotEmpty) {
                      return PermissionResponse(
                        resources: grantedResources,
                        action: PermissionResponseAction.GRANT,
                      );
                    }
                    return PermissionResponse(
                      resources: request.resources,
                      action: PermissionResponseAction.DENY,
                    );
                  },
                  onReceivedServerTrustAuthRequest: (controller, challenge) async {
                    if (ENABLE_SSL_PINNING && SSL_PINS.isNotEmpty) {
                      try {
                        final certBytes = challenge.protectionSpace.sslCertificate?.x509Certificate?.encoded;
                        if (certBytes != null && certBytes.isNotEmpty) {
                          final certHash = sha256.convert(certBytes).toString().toLowerCase();
                          final rawPins = SSL_PINS
                              .split(',')
                              .map((p) => p.replaceAll(':', '').replaceAll(' ', '').trim().toLowerCase())
                              .where((p) => p.isNotEmpty)
                              .toList();
                          if (rawPins.contains(certHash)) {
                            return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
                          }
                        }
                        debugPrint('SSL Pinning failed: Certificate fingerprint mismatch');
                        return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.CANCEL);
                      } catch (e) {
                        debugPrint('SSL Pinning verification error: $e');
                        return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.CANCEL);
                      }
                    }
                    return ServerTrustAuthResponse(action: ServerTrustAuthResponseAction.PROCEED);
                  },
                  onWebViewCreated: (controller) {
                    webViewController = controller;

                    /// ===== Auth State JS Bridge =====
                    controller.addJavaScriptHandler(
                      handlerName: 'authStateChanged',
                      callback: (args) {
                        if (args.isNotEmpty && mounted) {
                          final bool loggedIn = args[0] == true;
                          if (isUserLoggedIn != loggedIn) {
                            setState(() {
                              isUserLoggedIn = loggedIn;
                            });
                          }
                        }
                        return null;
                      },
                    );

                    /// ===== Clipboard JS Bridge =====
                    controller.addJavaScriptHandler(
                      handlerName: 'clipboard',
                      callback: (args) async {
                        final action = args[0];

                        if (action == 'copy') {
                          final text = args[1] as String;
                          await ClipboardChannel.copyText(text);
                          return true;
                        }

                        if (action == 'paste') {
                          final text = await ClipboardChannel.pasteText();
                          return text;
                        }

                        return null;
                      },
                    );

                    /// ===== Secure Storage JS Bridge =====
                    if (ENABLE_SECURE_STORAGE) {
                      controller.addJavaScriptHandler(
                        handlerName: 'secureStorage',
                        callback: (args) async {
                          try {
                            if (args.isEmpty) return null;
                            final action = args[0] as String;
                            if (action == 'setItem' && args.length >= 3) {
                              await _secureStorage.write(
                                key: args[1] as String,
                                value: args[2] as String,
                              );
                              return true;
                            } else if (action == 'getItem' && args.length >= 2) {
                              return await _secureStorage.read(
                                key: args[1] as String,
                              );
                            } else if (action == 'removeItem' && args.length >= 2) {
                              await _secureStorage.delete(
                                key: args[1] as String,
                              );
                              return true;
                            } else if (action == 'clear') {
                              await _secureStorage.deleteAll();
                              return true;
                            }
                          } catch (e) {
                            debugPrint('SecureStorage JS Bridge error: $e');
                          }
                          return null;
                        },
                      );
                    }
                  },
                  onLoadStart: (controller, url) {
                    setState(() {
                      isLoading = true;
                    });
                  },
                  onLoadStop: (controller, url) async {
                    pullToRefreshController?.endRefreshing();
                    setState(() {
                      isLoading = false;
                      isOffline = false;
                    });
                    if (ENABLE_SECURE_STORAGE) {
                      await controller.evaluateJavascript(
                        source: '''
                          if (!window.NativeSecureStorage) {
                            window.NativeSecureStorage = {
                              setItem: function(key, val) {
                                return window.flutter_inappwebview.callHandler('secureStorage', 'setItem', key, String(val));
                              },
                              getItem: function(key) {
                                return window.flutter_inappwebview.callHandler('secureStorage', 'getItem', key);
                              },
                              removeItem: function(key) {
                                return window.flutter_inappwebview.callHandler('secureStorage', 'removeItem', key);
                              },
                              clear: function() {
                                return window.flutter_inappwebview.callHandler('secureStorage', 'clear');
                              }
                            };
                          }
                        ''',
                      );
                    }
                    if (SHOW_NAVIGATION_BAR || SHOW_NAVIGATION_BAR_2) {
                      await _injectAuthDetector(controller);
                    }
                    if (SHOW_NAVIGATION_BAR_2) {
                      await _injectFloatingNavbar2(controller);
                    }
                    await _updateNavigationState();
                  },
                  onProgressChanged: (controller, progress) {
                    if (progress == 100) {
                      pullToRefreshController?.endRefreshing();
                    }
                    setState(() {
                      this.progress = progress / 100;
                      isLoading = progress < 100;
                    });
                  },
                  onReceivedError: (controller, request, error) {
                    pullToRefreshController?.endRefreshing();
                    if (request.isForMainFrame ?? true) {
                      setState(() {
                        isOffline = true;
                      });
                    }
                  },
                  shouldOverrideUrlLoading:
                      (controller, navigationAction) async {
                        final uri = navigationAction.request.url;
                        if (uri != null) {
                          final urlString = uri.toString();
                          if (!urlString.startsWith('http://') &&
                              !urlString.startsWith('https://')) {
                            if (await canLaunchUrl(uri)) {
                              await launchUrl(
                                uri,
                                mode: LaunchMode.externalApplication,
                              );
                              return NavigationActionPolicy.CANCEL;
                            }
                          }
                        }
                        return NavigationActionPolicy.ALLOW;
                      },
                  onDownloadStartRequest:
                      (controller, downloadStartRequest) async {
                        final downloadUrl = downloadStartRequest.url.toString();
                        if (await canLaunchUrl(Uri.parse(downloadUrl))) {
                          await launchUrl(
                            Uri.parse(downloadUrl),
                            mode: LaunchMode.externalApplication,
                          );
                        }
                      },
                ),
              if (isLoading && !isOffline && !_isLocked && !_showSplash)
                Positioned(
                  top: 0,
                  left: 0,
                  right: 0,
                  child: LinearProgressIndicator(
                    value: progress,
                    backgroundColor: Colors.grey[200],
                    valueColor: const AlwaysStoppedAnimation<Color>(
                      Colors.blue,
                    ),
                  ),
                ),
              if (isOffline && !isWebView2Missing && ENABLE_ERROR_PAGE)
                Positioned.fill(child: _buildOfflineWidget()),
              if (_showSplash)
                Positioned.fill(child: _buildSplashScreen()),
              if (_isLocked)
                _buildLockScreen(),
            ],
          ),
        ),
        bottomNavigationBar: !SHOW_NAVIGATION_BAR || (isOffline && ENABLE_ERROR_PAGE) || _isLocked || _showSplash
            ? null
            : Container(
                decoration: BoxDecoration(
                  color: Theme.of(context).scaffoldBackgroundColor,
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0x1A000000),
                      blurRadius: 10,
                      offset: const Offset(0, -2),
                    ),
                  ],
                ),
                child: SafeArea(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                      children: [
                        IconButton(
                          icon: Icon(
                            Icons.arrow_back_ios,
                            color: canGoBack ? null : Colors.grey,
                          ),
                          onPressed: canGoBack
                              ? () => webViewController?.goBack()
                              : null,
                        ),
                        IconButton(
                          icon: Icon(
                            Icons.arrow_forward_ios,
                            color: canGoForward ? null : Colors.grey,
                          ),
                          onPressed: canGoForward
                              ? () => webViewController?.goForward()
                              : null,
                        ),
                        IconButton(
                          icon: const Icon(Icons.refresh),
                          onPressed: () => webViewController?.reload(),
                        ),
                        if (!isUserLoggedIn)
                          IconButton(
                            icon: const Icon(Icons.home),
                            onPressed: () {
                              webViewController?.loadUrl(
                                urlRequest: URLRequest(url: WebUri(url)),
                              );
                            },
                          ),
                        IconButton(
                          icon: const Icon(Icons.share),
                          onPressed: () async {
                            final currentUrl =
                                await webViewController?.getUrl();
                            if (currentUrl != null) {
                              await share_plus.Share.share(
                                currentUrl.toString(),
                              );
                            }
                          },
                        ),
                      ],
                    ),
                  ),
                ),
              ),
      ),
    );
  }

  Color _parseHexColor(String hexString, Color defaultColor) {
    try {
      String cleanHex = hexString.replaceAll('#', '').trim();
      if (cleanHex.length == 6) {
        return Color(int.parse('FF$cleanHex', radix: 16));
      } else if (cleanHex.length == 8) {
        return Color(int.parse(cleanHex, radix: 16));
      }
      return defaultColor;
    } catch (e) {
      return defaultColor;
    }
  }

  Widget _buildSplashScreen() {
    final bgColor = _parseHexColor(SPLASH_BG_COLOR, Colors.white);
    final textColor = _parseHexColor(SPLASH_TEXT_COLOR, const Color(0xFF1E293B));

    return Container(
      color: bgColor,
      width: double.infinity,
      height: double.infinity,
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              if (HAS_CUSTOM_SPLASH_IMAGE)
                Image.asset(
                  'assets/splash.png',
                  width: 140,
                  height: 140,
                  fit: BoxFit.contain,
                  errorBuilder: (context, error, stackTrace) => _buildFallbackSplashIcon(textColor),
                )
              else
                _buildFallbackSplashIcon(textColor),
              const SizedBox(height: 24),
              if (SPLASH_TITLE.isNotEmpty)
                Text(
                  SPLASH_TITLE,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 26,
                    fontWeight: FontWeight.bold,
                    color: textColor,
                    letterSpacing: 0.5,
                  ),
                ),
              if (SPLASH_SUBTITLE.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  SPLASH_SUBTITLE,
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 15,
                    color: textColor.withOpacity(0.8),
                    letterSpacing: 0.2,
                  ),
                ),
              ],
              const SizedBox(height: 36),
              SizedBox(
                width: 28,
                height: 28,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  valueColor: AlwaysStoppedAnimation<Color>(textColor.withOpacity(0.7)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFallbackSplashIcon(Color color) {
    return Container(
      width: 100,
      height: 100,
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        shape: BoxShape.circle,
      ),
      child: Icon(
        Icons.rocket_launch_rounded,
        size: 52,
        color: color,
      ),
    );
  }

  Widget _buildOfflineWidget() {
    final bgColor = _parseHexColor(ERROR_BG_COLOR, Colors.white);
    final textColor = _parseHexColor(ERROR_TEXT_COLOR, const Color(0xFF334155));

    return Container(
      color: bgColor,
      width: double.infinity,
      height: double.infinity,
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              if (HAS_CUSTOM_ERROR_IMAGE)
                Image.asset(
                  'assets/error.png',
                  width: 140,
                  height: 140,
                  fit: BoxFit.contain,
                  errorBuilder: (context, error, stackTrace) => _buildFallbackErrorIcon(textColor),
                )
              else
                _buildFallbackErrorIcon(textColor),
              const SizedBox(height: 24),
              Text(
                ERROR_TITLE.isNotEmpty ? ERROR_TITLE : 'No Internet Connection',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color: textColor,
                ),
              ),
              const SizedBox(height: 10),
              Text(
                ERROR_MESSAGE.isNotEmpty ? ERROR_MESSAGE : 'Please check your connection and try again',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 15,
                  color: textColor.withOpacity(0.75),
                ),
              ),
              const SizedBox(height: 32),
              ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: textColor,
                  foregroundColor: bgColor,
                  padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                onPressed: () async {
                  await _checkConnectivity();
                  webViewController?.reload();
                },
                icon: const Icon(Icons.refresh),
                label: Text(
                  ERROR_BUTTON_TEXT.isNotEmpty ? ERROR_BUTTON_TEXT : 'Retry',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 16),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFallbackErrorIcon(Color color) {
    return Container(
      width: 100,
      height: 100,
      decoration: BoxDecoration(
        color: Colors.redAccent.withOpacity(0.1),
        shape: BoxShape.circle,
      ),
      child: const Icon(
        Icons.wifi_off_rounded,
        size: 54,
        color: Colors.redAccent,
      ),
    );
  }

  Widget _buildWebView2MissingWidget() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.warning_amber_rounded, size: 80, color: Colors.orange),
            const SizedBox(height: 20),
            const Text(
              'Microsoft Edge WebView2 Required',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            const Text(
              'To run this application on Windows, the Microsoft Edge WebView2 Runtime is required.\nMost Windows 10 and 11 systems already have it installed.',
              style: TextStyle(fontSize: 14, color: Colors.grey),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: () async {
                final uri = Uri.parse('https://go.microsoft.com/fwlink/p/?LinkId=2124703');
                if (await canLaunchUrl(uri)) {
                  await launchUrl(uri, mode: LaunchMode.externalApplication);
                }
              },
              icon: const Icon(Icons.download),
              label: const Text('Download WebView2 Runtime'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLockScreen() {
    final theme = Theme.of(context);
    final targetPin = APP_LOCK_PIN.trim();
    final pinLength = targetPin.isNotEmpty ? targetPin.length : 4;

    return Container(
      color: theme.scaffoldBackgroundColor,
      width: double.infinity,
      height: double.infinity,
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Container(
                width: 76,
                height: 76,
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withOpacity(0.12),
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  Icons.lock_rounded,
                  size: 38,
                  color: theme.colorScheme.primary,
                ),
              ),
              const SizedBox(height: 20),
              Text(
                'Security Lock',
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                ENABLE_APP_LOCK
                    ? 'Enter your passcode to unlock'
                    : 'Biometric authentication required',
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.textTheme.bodyMedium?.color?.withOpacity(0.65),
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              if (ENABLE_APP_LOCK) ...[
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: List.generate(pinLength, (index) {
                    final isFilled = index < _enteredPin.length;
                    return Container(
                      margin: const EdgeInsets.symmetric(horizontal: 8),
                      width: 16,
                      height: 16,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: isFilled
                            ? theme.colorScheme.primary
                            : theme.colorScheme.primary.withOpacity(0.18),
                        border: Border.all(
                          color: theme.colorScheme.primary,
                          width: 1.5,
                        ),
                      ),
                    );
                  }),
                ),
                const SizedBox(height: 16),
                if (_pinErrorMessage.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: Text(
                      _pinErrorMessage,
                      style: const TextStyle(
                        color: Colors.redAccent,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                const SizedBox(height: 12),
                SizedBox(
                  width: 280,
                  child: Column(
                    children: [
                      for (int row = 0; row < 3; row++)
                        Padding(
                          padding: const EdgeInsets.symmetric(vertical: 6),
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                            children: [
                              for (int col = 1; col <= 3; col++)
                                _buildKeypadButton('${row * 3 + col}'),
                            ],
                          ),
                        ),
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 6),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                          children: [
                            ENABLE_BIOMETRIC_AUTH
                                ? _buildIconButton(
                                    Icons.fingerprint_rounded,
                                    _authenticateWithBiometrics,
                                  )
                                : const SizedBox(width: 68, height: 68),
                            _buildKeypadButton('0'),
                            _buildIconButton(
                              Icons.backspace_outlined,
                              _onDeletePressed,
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ] else if (ENABLE_BIOMETRIC_AUTH) ...[
                const SizedBox(height: 16),
                ElevatedButton.icon(
                  onPressed: _authenticateWithBiometrics,
                  icon: const Icon(Icons.fingerprint_rounded),
                  label: const Text('Unlock with Biometrics'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 24,
                      vertical: 14,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildKeypadButton(String digit) {
    final theme = Theme.of(context);
    return SizedBox(
      width: 68,
      height: 68,
      child: OutlinedButton(
        style: OutlinedButton.styleFrom(
          shape: const CircleBorder(),
          padding: EdgeInsets.zero,
          side: BorderSide(
            color: theme.dividerColor.withOpacity(0.4),
            width: 1,
          ),
          backgroundColor: theme.colorScheme.surface,
        ),
        onPressed: () => _onDigitPressed(digit),
        child: Text(
          digit,
          style: theme.textTheme.headlineSmall?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  Widget _buildIconButton(IconData icon, VoidCallback onPressed) {
    final theme = Theme.of(context);
    return SizedBox(
      width: 68,
      height: 68,
      child: IconButton(
        iconSize: 28,
        color: theme.colorScheme.primary,
        icon: Icon(icon),
        onPressed: onPressed,
      ),
    );
  }

  Future<void> _injectAuthDetector(InAppWebViewController controller) async {
    try {
      final escapedHomeUrl = url.replaceAll(r'\', r'\\').replaceAll("'", r"\'");
      await controller.evaluateJavascript(source: """
(function() {
  window.__iewn_home_url = '$escapedHomeUrl';

  function checkIsLoggedIn() {
    try {
      var path = (window.location.pathname || '').toLowerCase();

      // If clearly on login, sign-in, or registration page, definitely not logged in
      var loginPaths = ['/login', '/signin', '/sign-in', '/signup', '/sign-up', '/register', '/admin/login', '/auth'];
      for (var i = 0; i < loginPaths.length; i++) {
        var lp = loginPaths[i];
        if (path === lp || path === lp + '/' || path.indexOf(lp + '?') === 0 || path.indexOf(lp + '#') === 0) {
          return false;
        }
      }

      // Check if page has an active login or registration form
      if (document.querySelector('form#login-form-element, form#signup-form-element, form[action*="login" i]')) {
        var pwd = document.querySelector('input[type="password"]');
        var loginBtn = document.querySelector('#login-btn, #show-login, [id*="login" i]');
        if (pwd && loginBtn) return false;
      }

      // 1. Explicit sign out / logout elements
      var logoutSelectors = [
        'a[href*="logout" i]',
        'a[href*="signout" i]',
        'a[href*="sign-out" i]',
        'a[href*="log-out" i]',
        'button[id*="logout" i]',
        'button[id*="signout" i]',
        'button[class*="logout" i]',
        'button[class*="signout" i]',
        'form[action*="logout" i]',
        'form[action*="signout" i]',
        '[data-action="logout"]',
        '[data-action="signout"]',
        '#logout-btn',
        '.toolbar-logout-btn'
      ];
      for (var j = 0; j < logoutSelectors.length; j++) {
        var el = document.querySelector(logoutSelectors[j]);
        if (el) return true;
      }

      // Check for elements with text "Sign Out" or "Log Out"
      var clickables = document.querySelectorAll('a, button, span, [role="button"]');
      for (var k = 0; k < clickables.length; k++) {
        var t = (clickables[k].innerText || clickables[k].textContent || '').trim().toLowerCase();
        if (t === 'sign out' || t === 'signout' || t === 'log out' || t === 'logout' || t === 'deconnexion' || t === 'cerrar sesión') {
          return true;
        }
      }

      // 2. Common authenticated paths
      var authPaths = ['/dashboard', '/admin', '/manage', '/profile', '/account', '/portal', '/console', '/workspace', '/my-account'];
      for (var m = 0; m < authPaths.length; m++) {
        if (path.indexOf(authPaths[m]) === 0 && path.indexOf('login') === -1) {
          return true;
        }
      }

      // 3. User profile / avatar selectors
      var userSelectors = [
        '.user-avatar',
        '.user-profile',
        '#user-menu',
        '.user-menu',
        '[data-user]',
        '.user-badge',
        '.account-dropdown',
        '#profile-dropdown'
      ];
      for (var n = 0; n < userSelectors.length; n++) {
        var userEl = document.querySelector(userSelectors[n]);
        if (userEl && userEl.offsetParent !== null) return true;
      }

      // 4. Firebase / custom auth globals
      if (window.FirebaseAppService && typeof window.FirebaseAppService.getCurrentUser === 'function') {
        if (window.FirebaseAppService.getCurrentUser()) return true;
      }
      if (window.firebase && window.firebase.auth && typeof window.firebase.auth === 'function') {
        try {
          if (window.firebase.auth().currentUser) return true;
        } catch(e) {}
      }

      // 5. Auth tokens in localStorage
      try {
        for (var p = 0; p < localStorage.length; p++) {
          var key = localStorage.key(p);
          if (key) {
            var lk = key.toLowerCase();
            if (lk === 'token' || lk === 'authtoken' || lk === 'jwt' || lk === 'session' || lk.indexOf('firebase:authuser') !== -1) {
              var val = localStorage.getItem(key);
              if (val && val !== 'null' && val !== 'undefined' && val !== '{}' && val !== 'false') {
                return true;
              }
            }
          }
        }
      } catch(e) {}

      return false;
    } catch(e) {
      return false;
    }
  }

  window.__iewn_check_logged_in = checkIsLoggedIn;

  function notifyAuthState() {
    var isLogged = checkIsLoggedIn();
    if (window.__iewn_last_logged_in !== isLogged) {
      window.__iewn_last_logged_in = isLogged;

      var homeBtn = document.getElementById('iewn-btn-home');
      if (homeBtn) {
        homeBtn.style.display = isLogged ? 'none' : 'flex';
      }

      if (window.flutter_inappwebview && typeof window.flutter_inappwebview.callHandler === 'function') {
        window.flutter_inappwebview.callHandler('authStateChanged', isLogged);
      }
    }
  }

  window.__iewn_last_logged_in = checkIsLoggedIn();
  notifyAuthState();

  if (!window.__iewn_auth_observer) {
    var debounceTimer = null;
    var observer = new MutationObserver(function() {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(notifyAuthState, 200);
    });
    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['class', 'style', 'href']
    });
    window.__iewn_auth_observer = observer;

    window.addEventListener('popstate', notifyAuthState);
    window.addEventListener('hashchange', notifyAuthState);
  }
})();
""");
    } catch (e) {
      debugPrint('Auth detector injection error: $e');
    }
  }

  Future<void> _injectFloatingNavbar2(InAppWebViewController controller) async {
    try {
      await controller.evaluateJavascript(source: r"""
(function() {
  if (window.__iewn_nav2_initialized) {
    if (window.__iewn_nav2_refresh) window.__iewn_nav2_refresh();
    return;
  }
  window.__iewn_nav2_initialized = true;

  // 1. Detect adaptive color scheme & theme
  function getAdaptiveTheme() {
    let accent = '#02a4cb';
    try {
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme && metaTheme.content) {
        accent = metaTheme.content.trim();
      } else {
        const header = document.querySelector('header, nav, .navbar');
        if (header) {
          const bg = window.getComputedStyle(header).backgroundColor;
          if (bg && bg !== 'transparent' && !bg.includes('rgba(0, 0, 0, 0)')) {
            accent = bg;
          }
        }
      }
    } catch(e) {}

    let isDark = false;
    try {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        isDark = true;
      }
      const bodyBg = window.getComputedStyle(document.body).backgroundColor;
      if (bodyBg && bodyBg.startsWith('rgb')) {
        const rgb = bodyBg.match(/\d+/g);
        if (rgb && rgb.length >= 3) {
          const brightness = (parseInt(rgb[0]) * 299 + parseInt(rgb[1]) * 587 + parseInt(rgb[2]) * 114) / 1000;
          if (brightness < 128) isDark = true;
        }
      }
    } catch(e) {}

    return {
      accent: accent || '#02a4cb',
      isDark: isDark,
      bg: isDark ? 'rgba(24, 30, 42, 0.96)' : '#ffffff',
      color: isDark ? '#f1f5f9' : '#1e293b',
      border: isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.08)',
      shadow: isDark ? '0 16px 40px rgba(0,0,0,0.6), 0 4px 12px rgba(0,0,0,0.4)' : '0 16px 40px rgba(0,0,0,0.14), 0 4px 12px rgba(0,0,0,0.06)'
    };
  }

  // 2. Scan and extract dynamic navigation links from the webpage
  function scanSiteNavigation() {
    const items = [];
    const seen = new Set();
    const currentOrigin = window.location.origin;

    let siteMenuBtn = document.querySelector('button[aria-label*="menu" i], .navbar-toggler, .menu-toggle, .hamburger, [data-bs-toggle="collapse"], [data-drawer-toggle], [aria-controls*="nav" i], [aria-controls*="menu" i]');

    const selectors = [
      'nav a[href]',
      'header a[href]',
      'aside a[href]',
      '.navbar a[href]',
      '.sidebar a[href]',
      '[role="navigation"] a[href]',
      '[role="menubar"] a[href]',
      '.nav a[href]',
      '.menu a[href]'
    ];
    let candidateLinks = document.querySelectorAll(selectors.join(', '));
    if (!candidateLinks || candidateLinks.length === 0) {
      candidateLinks = document.querySelectorAll('a[href]');
    }

    candidateLinks.forEach(a => {
      try {
        const href = a.getAttribute('href');
        if (!href || href === '#' || href.startsWith('javascript:') || href.startsWith('tel:') || href.startsWith('mailto:')) return;
        const fullUrl = a.href;
        if (!fullUrl || !fullUrl.startsWith('http')) return;
        try {
          const u = new URL(fullUrl);
          if (u.origin !== currentOrigin && !u.hostname.endsWith(window.location.hostname)) return;
        } catch(e) { return; }

        let text = (a.innerText || a.getAttribute('aria-label') || a.getAttribute('title') || '').trim();
        text = text.replace(/\s+/g, ' ');
        if (!text || text.length < 2 || text.length > 50) return;

        const key = text.toLowerCase() + '|' + fullUrl;
        if (!seen.has(key)) {
          seen.add(key);
          items.push({ text: text, href: fullUrl });
        }
      } catch(e) {}
    });

    return {
      links: items.slice(0, 25),
      hasSiteMenuToggle: !!siteMenuBtn,
      triggerSiteMenu: function() {
        if (siteMenuBtn) {
          siteMenuBtn.click();
          return true;
        }
        return false;
      }
    };
  }

  // 3. Create Container
  let theme = getAdaptiveTheme();
  let root = document.getElementById('__iewn_nav2_root');
  if (root) root.remove();

  root = document.createElement('div');
  root.id = '__iewn_nav2_root';
  root.style.cssText = 'position:fixed; z-index:2147483647; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; user-select:none; -webkit-user-select:none;';
  document.body.appendChild(root);

  let savedPos = null;
  try {
    savedPos = JSON.parse(localStorage.getItem('__iewn_nav2_pos'));
  } catch(e) {}

  let posX = (savedPos && typeof savedPos.x === 'number') ? savedPos.x : (window.innerWidth - 76);
  let posY = (savedPos && typeof savedPos.y === 'number') ? savedPos.y : Math.max(80, window.innerHeight / 2 - 140);
  posX = Math.max(10, Math.min(window.innerWidth - 66, posX));
  posY = Math.max(10, Math.min(window.innerHeight - 300, posY));

  let isExpanded = false;
  let isDragging = false;
  let startX = 0, startY = 0, initialPosX = 0, initialPosY = 0;
  let hasMoved = false;

  function render() {
    theme = getAdaptiveTheme();
    const isLoggedIn = (typeof window.__iewn_check_logged_in === 'function') ? window.__iewn_check_logged_in() : false;
    root.style.left = posX + 'px';
    root.style.top = posY + 'px';

    root.innerHTML = `
      <style>
        #__iewn_nav2_root * { box-sizing: border-box; margin:0; padding:0; }
        .iewn-bubble-btn {
          width: 52px;
          height: 52px;
          border-radius: 50%;
          background: ${theme.bg};
          border: 1px solid ${theme.border};
          box-shadow: ${theme.shadow};
          display: ${isExpanded ? 'none' : 'flex'};
          align-items: center;
          justify-content: center;
          cursor: grab;
          color: ${theme.color};
          transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.2s ease, background 0.2s ease;
          position: relative;
        }
        .iewn-bubble-btn:hover {
          transform: scale(1.08);
          box-shadow: 0 18px 45px rgba(0,0,0,0.22);
        }
        .iewn-bubble-btn:active {
          cursor: grabbing;
          transform: scale(0.96);
        }
        .iewn-bubble-badge {
          position: absolute;
          top: 0;
          right: 0;
          width: 14px;
          height: 14px;
          border-radius: 50%;
          background: ${theme.accent};
          border: 2px solid ${theme.bg};
        }

        /* Vertical Capsule Dock matching Image 3 */
        .iewn-dock {
          width: 56px;
          border-radius: 9999px;
          background: ${theme.bg};
          border: 1px solid ${theme.border};
          box-shadow: ${theme.shadow};
          padding: 16px 0;
          display: ${isExpanded ? 'flex' : 'none'};
          flex-direction: column;
          align-items: center;
          gap: 10px;
          cursor: grab;
          position: relative;
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          animation: iewnDockPop 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
        }
        .iewn-dock:active { cursor: grabbing; }

        @keyframes iewnDockPop {
          0% { opacity: 0; transform: scale(0.85) translateY(10px); }
          100% { opacity: 1; transform: scale(1) translateY(0); }
        }

        .iewn-item {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          background: transparent;
          border: none;
          color: ${theme.color};
          cursor: pointer;
          position: relative;
          transition: all 0.2s ease;
        }
        .iewn-item:hover {
          background: ${theme.isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.05)'};
          color: ${theme.accent};
          transform: scale(1.08);
        }
        .iewn-item svg {
          width: 20px;
          height: 20px;
          stroke: currentColor;
          fill: none;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
        }

        /* Adaptive Tooltip Pill matching Image 3 */
        .iewn-pill-tooltip {
          position: absolute;
          ${posX > (window.innerWidth / 2) ? 'right: 52px;' : 'left: 52px;'}
          top: 50%;
          transform: translateY(-50%) scale(0.9);
          background: ${theme.accent};
          color: #ffffff;
          padding: 8px 14px;
          border-radius: 9999px;
          font-size: 13px;
          font-weight: 600;
          display: flex;
          align-items: center;
          gap: 8px;
          white-space: nowrap;
          pointer-events: none;
          opacity: 0;
          box-shadow: 0 8px 24px rgba(0,0,0,0.2);
          transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
          z-index: 20;
        }
        .iewn-item:hover .iewn-pill-tooltip {
          opacity: 1;
          transform: translateY(-50%) scale(1);
        }

        /* Site Pages Flyout Menu */
        .iewn-pages-flyout {
          position: absolute;
          ${posX > (window.innerWidth / 2) ? 'right: 68px;' : 'left: 68px;'}
          top: 0;
          width: 260px;
          max-height: 400px;
          background: ${theme.bg};
          border: 1px solid ${theme.border};
          border-radius: 18px;
          box-shadow: ${theme.shadow};
          display: none;
          flex-direction: column;
          overflow: hidden;
          z-index: 30;
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          animation: iewnFlyout 0.2s ease forwards;
        }
        @keyframes iewnFlyout {
          0% { opacity: 0; transform: scale(0.95) translateX(${posX > (window.innerWidth / 2) ? '10px' : '-10px'}); }
          100% { opacity: 1; transform: scale(1) translateX(0); }
        }
        .iewn-flyout-header {
          padding: 12px 16px;
          border-bottom: 1px solid ${theme.border};
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-weight: 700;
          font-size: 13px;
          color: ${theme.color};
        }
        .iewn-flyout-close {
          background: none;
          border: none;
          cursor: pointer;
          color: #94a3b8;
          font-size: 16px;
          padding: 2px 6px;
        }
        .iewn-flyout-body {
          overflow-y: auto;
          max-height: 330px;
          padding: 8px;
        }
        .iewn-flyout-link {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 8px 12px;
          border-radius: 10px;
          color: ${theme.color};
          text-decoration: none;
          font-size: 13px;
          font-weight: 500;
          transition: all 0.15s ease;
          cursor: pointer;
        }
        .iewn-flyout-link:hover {
          background: ${theme.isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.05)'};
          color: ${theme.accent};
          transform: translateX(3px);
        }
        .iewn-flyout-native-btn {
          width: 100%;
          padding: 9px 12px;
          margin-bottom: 8px;
          border-radius: 10px;
          background: ${theme.accent};
          color: #fff;
          border: none;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
        }
      </style>

      <!-- Bubble Button (Collapsed) -->
      <div class="iewn-bubble-btn" id="iewn-bubble" title="Navigation Bar 2 (Click or double-tap empty screen to open)">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"></polygon>
        </svg>
        <span class="iewn-bubble-badge"></span>
      </div>

      <!-- Vertical Capsule Dock (Expanded) -->
      <div class="iewn-dock" id="iewn-dock">
        <!-- Home (shown only when user is not signed in) -->
        <button type="button" class="iewn-item" id="iewn-btn-home" aria-label="Home" style="${isLoggedIn ? 'display:none;' : ''}">
          <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
          <div class="iewn-pill-tooltip">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
            <span>Home</span>
          </div>
        </button>

        <!-- Backward -->
        <button type="button" class="iewn-item" id="iewn-btn-back" aria-label="Backward">
          <svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"></polyline></svg>
          <div class="iewn-pill-tooltip">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"></polyline></svg>
            <span>Backward</span>
          </div>
        </button>

        <!-- Forward -->
        <button type="button" class="iewn-item" id="iewn-btn-forward" aria-label="Forward">
          <svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"></polyline></svg>
          <div class="iewn-pill-tooltip">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"></polyline></svg>
            <span>Forward</span>
          </div>
        </button>

        <!-- Refresh -->
        <button type="button" class="iewn-item" id="iewn-btn-refresh" aria-label="Refresh">
          <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
          <div class="iewn-pill-tooltip">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"></path></svg>
            <span>Refresh</span>
          </div>
        </button>

        <!-- Menu (Dynamic Site Navigation) -->
        <button type="button" class="iewn-item" id="iewn-btn-menu" aria-label="Menu">
          <svg viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
          <div class="iewn-pill-tooltip">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            <span>Menu</span>
          </div>
        </button>

        <!-- Minimize -->
        <button type="button" class="iewn-item" id="iewn-btn-collapse" aria-label="Collapse" style="opacity:0.6;">
          <svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"></line></svg>
        </button>

        <!-- Site Pages Flyout -->
        <div class="iewn-pages-flyout" id="iewn-pages-flyout">
          <div class="iewn-flyout-header">
            <span>Website Pages</span>
            <button class="iewn-flyout-close" id="iewn-flyout-close">✕</button>
          </div>
          <div class="iewn-flyout-body" id="iewn-flyout-list">
            <!-- Dynamically populated -->
          </div>
        </div>
      </div>
    `;

    attachEvents();
  }

  function attachEvents() {
    const bubble = document.getElementById('iewn-bubble');
    const dock = document.getElementById('iewn-dock');
    const flyout = document.getElementById('iewn-pages-flyout');
    const flyoutList = document.getElementById('iewn-flyout-list');
    const flyoutClose = document.getElementById('iewn-flyout-close');

    [bubble, dock].forEach(el => {
      if (!el) return;
      el.addEventListener('mousedown', onDragStart);
      el.addEventListener('touchstart', onDragStart, { passive: false });
    });

    function onDragStart(e) {
      if (e.target.closest('button') && isExpanded && !e.target.closest('#iewn-dock')) {
        return;
      }
      isDragging = true;
      hasMoved = false;
      const clientX = e.touches ? e.touches[0].clientX : e.clientX;
      const clientY = e.touches ? e.touches[0].clientY : e.clientY;
      startX = clientX;
      startY = clientY;
      initialPosX = posX;
      initialPosY = posY;

      document.addEventListener('mousemove', onDragMove);
      document.addEventListener('mouseup', onDragEnd);
      document.addEventListener('touchmove', onDragMove, { passive: false });
      document.addEventListener('touchend', onDragEnd);
    }

    function onDragMove(e) {
      if (!isDragging) return;
      const clientX = e.touches ? e.touches[0].clientX : e.clientX;
      const clientY = e.touches ? e.touches[0].clientY : e.clientY;
      const dx = clientX - startX;
      const dy = clientY - startY;

      if (Math.abs(dx) > 4 || Math.abs(dy) > 4) {
        hasMoved = true;
        if (e.cancelable) e.preventDefault();
      }

      posX = Math.max(8, Math.min(window.innerWidth - 64, initialPosX + dx));
      posY = Math.max(8, Math.min(window.innerHeight - (isExpanded ? 320 : 64), initialPosY + dy));
      root.style.left = posX + 'px';
      root.style.top = posY + 'px';
    }

    function onDragEnd() {
      if (!isDragging) return;
      isDragging = false;
      document.removeEventListener('mousemove', onDragMove);
      document.removeEventListener('mouseup', onDragEnd);
      document.removeEventListener('touchmove', onDragMove);
      document.removeEventListener('touchend', onDragEnd);

      try {
        localStorage.setItem('__iewn_nav2_pos', JSON.stringify({ x: posX, y: posY }));
      } catch(e) {}
    }

    if (bubble) {
      bubble.addEventListener('click', () => {
        if (hasMoved) return;
        isExpanded = true;
        render();
      });
    }

    const collapseBtn = document.getElementById('iewn-btn-collapse');
    if (collapseBtn) {
      collapseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        isExpanded = false;
        render();
      });
    }

    document.getElementById('iewn-btn-home')?.addEventListener('click', (e) => {
      e.stopPropagation();
      window.location.href = window.__iewn_home_url || window.location.origin;
    });

    document.getElementById('iewn-btn-back')?.addEventListener('click', (e) => {
      e.stopPropagation();
      window.history.back();
    });

    document.getElementById('iewn-btn-forward')?.addEventListener('click', (e) => {
      e.stopPropagation();
      window.history.forward();
    });

    document.getElementById('iewn-btn-refresh')?.addEventListener('click', (e) => {
      e.stopPropagation();
      window.location.reload();
    });

    document.getElementById('iewn-btn-menu')?.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!flyout) return;
      if (flyout.style.display === 'flex') {
        flyout.style.display = 'none';
        return;
      }

      const navInfo = scanSiteNavigation();
      let html = '';

      if (navInfo.hasSiteMenuToggle) {
        html += `<button type="button" class="iewn-flyout-native-btn" id="iewn-native-toggle-btn">
          <svg style="width:14px;height:14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
          Open Site Menu Drawer
        </button>`;
      }

      if (navInfo.links.length > 0) {
        navInfo.links.forEach(l => {
          html += `<div class="iewn-flyout-link" data-href="${encodeURI(l.href)}">
            <svg style="width:14px;height:14px;opacity:0.7;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
            <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${l.text}</span>
          </div>`;
        });
      } else {
        html += `<div style="padding:16px;text-align:center;font-size:12px;opacity:0.7;">No additional navigation links detected on this page.</div>`;
      }

      flyoutList.innerHTML = html;
      flyout.style.display = 'flex';

      flyoutList.querySelectorAll('.iewn-flyout-link').forEach(item => {
        item.addEventListener('click', () => {
          const targetHref = item.getAttribute('data-href');
          if (targetHref) {
            window.location.href = decodeURI(targetHref);
          }
        });
      });

      const nativeBtn = document.getElementById('iewn-native-toggle-btn');
      if (nativeBtn) {
        nativeBtn.addEventListener('click', () => {
          navInfo.triggerSiteMenu();
          flyout.style.display = 'none';
        });
      }
    });

    if (flyoutClose) {
      flyoutClose.addEventListener('click', (e) => {
        e.stopPropagation();
        flyout.style.display = 'none';
      });
    }
  }

  function handleEmptyAreaDblClick(e) {
    if (e.target && (e.target.closest('a, button, input, textarea, select, [role="button"]') || e.target.isContentEditable)) {
      return;
    }
    if (root.contains(e.target)) return;

    isExpanded = !isExpanded;
    render();
  }

  document.addEventListener('dblclick', handleEmptyAreaDblClick);

  let lastTapTime = 0;
  document.addEventListener('touchend', (e) => {
    const now = Date.now();
    if (now - lastTapTime < 300) {
      handleEmptyAreaDblClick(e);
    }
    lastTapTime = now;
  }, { passive: true });

  window.__iewn_nav2_refresh = function() {
    render();
  };

  render();
})();
""");
    } catch (e) {
      debugPrint('Floating Navbar 2 injection error: $e');
    }
  }

}
