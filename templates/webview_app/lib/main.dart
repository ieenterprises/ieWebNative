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
  bool isWebView2Missing = false;

  bool get isMobile => !kIsWeb && (defaultTargetPlatform == TargetPlatform.android || defaultTargetPlatform == TargetPlatform.iOS);

  static const bool ALLOW_ZOOM = false;
  static const bool ENABLE_JAVASCRIPT = false;
  static const bool ENABLE_DOM_STORAGE = false;
  static const bool ENABLE_GEOLOCATION = false;
  static const bool ENABLE_PULL_TO_REFRESH = false;
  static const bool SHOW_NAVIGATION_BAR = false;
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
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
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
    }
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
      if (mounted) {
        setState(() {
          isOffline = connectivityResult.contains(ConnectivityResult.none);
        });
      }

      Connectivity().onConnectivityChanged.listen((result) {
        if (mounted) {
          setState(() {
            isOffline = result.contains(ConnectivityResult.none);
          });
          if (!isOffline) {
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
    setState(() {
      canGoBack = canBack;
      canGoForward = canForward;
    });
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
                    useHybridComposition: defaultTargetPlatform == TargetPlatform.android,
                  ),
                  pullToRefreshController: isMobile ? pullToRefreshController : null,
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
                      if (_showSplash) _showSplash = false;
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
}
