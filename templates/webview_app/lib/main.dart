import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:share_plus/share_plus.dart' as share_plus;
import 'package:permission_handler/permission_handler.dart';

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

class _WebViewScreenState extends State<WebViewScreen> {
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

  static const bool ALLOW_ZOOM = true;
  static const bool ENABLE_JAVASCRIPT = true;
  static const bool ENABLE_DOM_STORAGE = true;
  static const bool ENABLE_GEOLOCATION = true;
  static const bool ENABLE_PULL_TO_REFRESH = true;
  static const bool SHOW_NAVIGATION_BAR = true;
  static const bool ENABLE_FILE_ACCESS = true;
  static const bool ENABLE_CACHE = true;
  static const bool ENABLE_MEDIA_AUTOPLAY = false;
  static const bool ENABLE_CAMERA = true;
  static const bool ENABLE_MICROPHONE = true;

  @override
  void initState() {
    super.initState();
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
      canPop: !canGoBack,
      onPopInvokedWithResult: (didPop, result) async {
        if (!didPop && canGoBack) {
          webViewController?.goBack();
        }
      },
      child: Scaffold(
        body: SafeArea(
          child: Stack(
            children: [
              if (isWebView2Missing)
                _buildWebView2MissingWidget()
              else if (isOffline)
                _buildOfflineWidget()
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
                  onWebViewCreated: (controller) {
                    webViewController = controller;

                    /// ===== Clipboard JS Bridge (ADDED) =====
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
                    /// ======================================
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
                    });
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
              if (isLoading && !isOffline)
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
            ],
          ),
        ),
        bottomNavigationBar: !SHOW_NAVIGATION_BAR || isOffline
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

  Widget _buildOfflineWidget() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.wifi_off, size: 80, color: Colors.grey[400]),
          const SizedBox(height: 20),
          Text(
            'No Internet Connection',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.grey[600],
            ),
          ),
          const SizedBox(height: 10),
          Text(
            'Please check your connection and try again',
            style: TextStyle(fontSize: 14, color: Colors.grey[500]),
          ),
          const SizedBox(height: 30),
          ElevatedButton.icon(
            onPressed: () async {
              await _checkConnectivity();
              if (!isOffline) {
                webViewController?.reload();
              }
            },
            icon: const Icon(Icons.refresh),
            label: const Text('Retry'),
          ),
        ],
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
}
