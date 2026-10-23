package com.wakex.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class MainActivity extends Activity {
    // --- Android KeyStore Cryptographic Storage ---
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEYSTORE_ALIAS = "WakeXSecretMasterKey";
    private static final String PREF_KEY_ENCRYPTED_SECRET = "wakex_encrypted_secret";

    private synchronized SecretKey getOrCreateMasterKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                keyGen.init(new KeyGenParameterSpec.Builder(
                        KEYSTORE_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build());
                return keyGen.generateKey();
            }
            return (SecretKey) keyStore.getKey(KEYSTORE_ALIAS, null);
        } catch (Exception e) {
            android.util.Log.e("WakeX.KeyStore", "KeyStore initialization error", e);
            return null;
        }
    }

    private void storeSecretInKeyStore(String secret) {
        if (secret == null || secret.isEmpty()) return;
        try {
            SecretKey key = getOrCreateMasterKey();
            if (key != null) {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] iv = cipher.getIV();
                byte[] encrypted = cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8));
                byte[] combined = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
                String base64Encrypted = Base64.encodeToString(combined, Base64.NO_WRAP);
                prefs.edit().putString(PREF_KEY_ENCRYPTED_SECRET, base64Encrypted).remove(PREF_KEY_CLIENT_SECRET).apply();
                return;
            }
        } catch (Exception e) {
            android.util.Log.e("WakeX.KeyStore", "Encryption error", e);
        }
        // Fallback for emulators without KeyStore support
        prefs.edit().putString(PREF_KEY_CLIENT_SECRET, secret).apply();
    }

    private String getSecretFromKeyStore() {
        String base64Encrypted = prefs.getString(PREF_KEY_ENCRYPTED_SECRET, "");
        if (!base64Encrypted.isEmpty()) {
            try {
                SecretKey key = getOrCreateMasterKey();
                if (key != null) {
                    byte[] combined = Base64.decode(base64Encrypted, Base64.NO_WRAP);
                    if (combined.length > 12) {
                        byte[] iv = new byte[12];
                        byte[] ciphertext = new byte[combined.length - 12];
                        System.arraycopy(combined, 0, iv, 0, 12);
                        System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);

                        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                        cipher.init(Cipher.DECRYPT_MODE, key, spec);
                        byte[] decrypted = cipher.doFinal(ciphertext);
                        return new String(decrypted, StandardCharsets.UTF_8);
                    }
                }
            } catch (Exception e) {
                android.util.Log.e("WakeX.KeyStore", "Decryption error", e);
            }
        }
        return prefs.getString(PREF_KEY_CLIENT_SECRET, "");
    }

    private WebView webView;
    private FrameLayout rootLayout;
    private LinearLayout errorLayout;
    private ProgressBar progressBar;
    private TextView errorUrlText;
    private TextView networkBanner;
    private EditText ipEditText;
    private SharedPreferences prefs;

    private static final String PREF_KEY_URL = "wakex_server_url";
    private static final String PREF_KEY_CLIENT_ID = "wakex_client_id";
    private static final String PREF_KEY_CLIENT_SECRET = "wakex_client_secret";
    private static final String PREF_KEY_DEVICE_MACS = "wakex_device_macs";

    // Current active PC IP on home Wi-Fi
    private static final String DEFAULT_URL = "http://192.168.1.100:8000";
    private boolean pageLoadFailed = false;
    private boolean pageLoadSuccess = false;

    private final Handler watchdogHandler = new Handler(Looper.getMainLooper());
    private static final int CONNECTION_TIMEOUT_MS = 6000;

    private final Runnable timeoutRunnable = new Runnable() {
        @Override
        public void run() {
            if (!pageLoadSuccess) {
                if (webView != null) {
                    webView.stopLoading();
                }
                pageLoadFailed = true;
                showErrorScreen("Connection Timed Out (No response from PC).\nEnsure your phone is on the same Wi-Fi as your PC.");
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        prefs = getSharedPreferences("WakeXPrefs", Context.MODE_PRIVATE);

        // Configure status and navigation bars for seamless dark theme
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            getWindow().setStatusBarColor(Color.parseColor("#080C14"));
            getWindow().setNavigationBarColor(Color.parseColor("#080C14"));
        }

        // Root container with dark tech background and system window insets
        rootLayout = new FrameLayout(this);
        rootLayout.setBackgroundColor(Color.parseColor("#080C14"));
        rootLayout.setFitsSystemWindows(true);

        // 1. Configure WebView with true mobile viewport
        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#080C14"));

        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowContentAccess(true);
        ws.setLoadWithOverviewMode(false);
        ws.setUseWideViewPort(false);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        ws.setCacheMode(WebSettings.LOAD_DEFAULT);

        try {
            WebView.setWebContentsDebuggingEnabled(true);
        } catch (Exception ignored) {}

        // JavaScript Interface for Native Wake-on-LAN and Credential Sync
        webView.addJavascriptInterface(new Object() {
            @JavascriptInterface
            public void sendWoL(String mac) {
                String savedMacs = prefs.getString(PREF_KEY_DEVICE_MACS, "00-11-22-33-44-55,00-AA-BB-CC-DD-EE");
                String[] macList = (mac != null && !mac.isEmpty()) 
                    ? new String[]{mac, "00-11-22-33-44-55", "00-AA-BB-CC-DD-EE"} 
                    : savedMacs.split(",");
                sendWakeOnLan(macList);
            }

            @JavascriptInterface
            public void saveCredentials(String clientId, String secret) {
                if (clientId != null && secret != null) {
                    prefs.edit().putString(PREF_KEY_CLIENT_ID, clientId).apply();
                    storeSecretInKeyStore(secret);
                }
            }

            @JavascriptInterface
            public String getClientId() {
                return prefs.getString(PREF_KEY_CLIENT_ID, "");
            }

            @JavascriptInterface
            public String getClientSecret() {
                return getSecretFromKeyStore();
            }

            @JavascriptInterface
            public String signRequest(String method, String path, String timestamp, String nonce, String bodyHash) {
                String secret = getSecretFromKeyStore();
                if (secret == null || secret.isEmpty()) return "";
                try {
                    String signString = method.toUpperCase(Locale.ROOT) + ":" + path + ":" + timestamp + ":" + nonce + ":" + bodyHash;
                    Mac hmac = Mac.getInstance("HmacSHA256");
                    SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
                    hmac.init(keySpec);
                    byte[] hash = hmac.doFinal(signString.getBytes(StandardCharsets.UTF_8));
                    StringBuilder hex = new StringBuilder();
                    for (byte b : hash) {
                        hex.append(String.format("%02x", b));
                    }
                    return hex.toString();
                } catch (Exception e) {
                    android.util.Log.e("WakeX.KeyStore", "Native HMAC sign error: " + e.getMessage());
                    return "";
                }
            }

            @JavascriptInterface
            public void cacheMacs(String macsCsv) {
                if (macsCsv != null && !macsCsv.isEmpty()) {
                    prefs.edit().putString(PREF_KEY_DEVICE_MACS, macsCsv).apply();
                }
            }
        }, "AndroidWakeX");

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                if (progressBar != null) {
                    if (newProgress < 100) {
                        progressBar.setVisibility(View.VISIBLE);
                        progressBar.setProgress(newProgress);
                    } else {
                        progressBar.setVisibility(View.GONE);
                    }
                }
                // Once DOM is rendered (>= 75%), mark success and disarm watchdog to eliminate black-screen hangs
                if (newProgress >= 75) {
                    pageLoadSuccess = true;
                    watchdogHandler.removeCallbacks(timeoutRunnable);
                }
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
                pageLoadFailed = false;
                pageLoadSuccess = false;
                if (progressBar != null) progressBar.setVisibility(View.VISIBLE);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    watchdogHandler.removeCallbacks(timeoutRunnable);
                    pageLoadFailed = true;
                    pageLoadSuccess = false;
                    showErrorScreen("Connection Failed: " + error.getDescription());
                }
            }

            @SuppressWarnings("deprecation")
            @Override
            public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
                watchdogHandler.removeCallbacks(timeoutRunnable);
                pageLoadFailed = true;
                pageLoadSuccess = false;
                showErrorScreen("Connection Failed (" + errorCode + "): " + description);
            }

            @Override
            public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
                if (request.isForMainFrame() && errorResponse.getStatusCode() >= 400 && errorResponse.getStatusCode() != 428) {
                    watchdogHandler.removeCallbacks(timeoutRunnable);
                    pageLoadFailed = true;
                    pageLoadSuccess = false;
                    showErrorScreen("Server Error: HTTP " + errorResponse.getStatusCode());
                }
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (progressBar != null) progressBar.setVisibility(View.GONE);
                if (!pageLoadFailed) {
                    watchdogHandler.removeCallbacks(timeoutRunnable);
                    pageLoadSuccess = true;
                    hideErrorScreen();
                }
            }
        });

        rootLayout.addView(webView, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
        ));

        // 2. Loading Progress Bar (Top)
        progressBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setProgressDrawable(getResources().getDrawable(android.R.drawable.progress_horizontal));
        FrameLayout.LayoutParams pbParams = new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpToPx(4)
        );
        pbParams.gravity = Gravity.TOP;
        rootLayout.addView(progressBar, pbParams);

        // 3. Build Native Error / Setup View
        buildErrorLayout();
        rootLayout.addView(errorLayout, new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
        ));

        // 4. Floating Settings Button (Allows changing IP anytime)
        Button settingsBtn = new Button(this);
        settingsBtn.setText("⚙️ IP");
        settingsBtn.setTextColor(Color.parseColor("#94A3B8"));
        settingsBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        settingsBtn.setBackgroundColor(Color.parseColor("#801E293B"));
        settingsBtn.setPadding(dpToPx(10), dpToPx(6), dpToPx(10), dpToPx(6));
        settingsBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showServerUrlDialog();
            }
        });

        FrameLayout.LayoutParams btnParams = new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        btnParams.gravity = Gravity.BOTTOM | Gravity.START;
        btnParams.setMargins(dpToPx(14), 0, 0, dpToPx(76));
        rootLayout.addView(settingsBtn, btnParams);

        setContentView(rootLayout);

        // Restore or load the server
        if (savedInstanceState != null) {
            webView.restoreState(savedInstanceState);
        } else {
            loadWakeX();
        }
    }


    @Override
    public void onConfigurationChanged(android.content.res.Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        // Fix rotation bugs: prevent white/black flash and keep layout responsive
        if (rootLayout != null) {
            rootLayout.requestLayout();
        }
        if (webView != null) {
            webView.requestLayout();
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (webView != null) {
            webView.saveState(outState);
        }
    }

    private boolean isConnectedToWifi() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    Network network = cm.getActiveNetwork();
                    if (network != null) {
                        NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                        return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
                    }
                } else {
                    @SuppressWarnings("deprecation")
                    NetworkInfo active = cm.getActiveNetworkInfo();
                    return active != null && active.isConnected() && active.getType() == ConnectivityManager.TYPE_WIFI;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private void updateNetworkBanner() {
        if (networkBanner == null) return;
        if (!isConnectedToWifi()) {
            networkBanner.setVisibility(View.VISIBLE);
            networkBanner.setText("⚠️ WARNING: Phone is on Cellular / Mobile Data.\nPlease connect your phone to your home Wi-Fi network to reach your PC.");
            networkBanner.setBackgroundColor(Color.parseColor("#7F1D1D"));
        } else {
            networkBanner.setVisibility(View.VISIBLE);
            networkBanner.setText("📶 Connected to Wi-Fi. Ready to reach PC.");
            networkBanner.setBackgroundColor(Color.parseColor("#064E3B"));
        }
    }

    private void buildErrorLayout() {
        errorLayout = new LinearLayout(this);
        errorLayout.setOrientation(LinearLayout.VERTICAL);
        errorLayout.setGravity(Gravity.CENTER);
        errorLayout.setBackgroundColor(Color.parseColor("#080C14"));
        errorLayout.setPadding(dpToPx(24), dpToPx(20), dpToPx(24), dpToPx(20));
        errorLayout.setVisibility(View.GONE);

        // Network status banner
        networkBanner = new TextView(this);
        networkBanner.setTextColor(Color.parseColor("#FFFFFF"));
        networkBanner.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        networkBanner.setTypeface(null, Typeface.BOLD);
        networkBanner.setGravity(Gravity.CENTER);
        networkBanner.setPadding(dpToPx(12), dpToPx(8), dpToPx(12), dpToPx(8));
        LinearLayout.LayoutParams bannerParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        bannerParams.setMargins(0, 0, 0, dpToPx(16));
        errorLayout.addView(networkBanner, bannerParams);

        // Icon
        TextView icon = new TextView(this);
        icon.setText("⚡");
        icon.setTextSize(TypedValue.COMPLEX_UNIT_SP, 44);
        icon.setGravity(Gravity.CENTER);
        errorLayout.addView(icon);

        // Title
        TextView title = new TextView(this);
        title.setText("WakeX Connection");
        title.setTextColor(Color.parseColor("#F59E0B"));
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTypeface(null, Typeface.BOLD);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, dpToPx(6), 0, dpToPx(4));
        errorLayout.addView(title);

        // Subtitle
        TextView sub = new TextView(this);
        sub.setText("Ensure your phone and PC are on the same Wi-Fi and WakeX is running.");
        sub.setTextColor(Color.parseColor("#94A3B8"));
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        sub.setGravity(Gravity.CENTER);
        sub.setPadding(0, 0, 0, dpToPx(14));
        errorLayout.addView(sub);

        // Error message text
        errorUrlText = new TextView(this);
        errorUrlText.setTextColor(Color.parseColor("#EF4444"));
        errorUrlText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        errorUrlText.setGravity(Gravity.CENTER);
        errorUrlText.setPadding(0, 0, 0, dpToPx(12));
        errorLayout.addView(errorUrlText);

        // IP Input Field
        ipEditText = new EditText(this);
        ipEditText.setTextColor(Color.parseColor("#FFFFFF"));
        ipEditText.setHintTextColor(Color.parseColor("#64748B"));
        ipEditText.setHint("e.g. 192.168.1.100:8000");
        ipEditText.setBackgroundColor(Color.parseColor("#1E293B"));
        ipEditText.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(12));
        ipEditText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        ipEditText.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams editParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        editParams.setMargins(0, 0, 0, dpToPx(14));
        errorLayout.addView(ipEditText, editParams);

        // 1-Tap Connect to PC Button
        Button connectBtn = new Button(this);
        connectBtn.setText("⚡ Connect to PC");
        connectBtn.setTextColor(Color.parseColor("#080C14"));
        connectBtn.setBackgroundColor(Color.parseColor("#F59E0B"));
        connectBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        connectBtn.setTypeface(null, Typeface.BOLD);
        connectBtn.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(12));
        connectBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String input = ipEditText.getText().toString().trim();
                if (input.isEmpty()) {
                    input = "192.168.1.100:8000";
                }
                prefs.edit().putString(PREF_KEY_URL, input).apply();
                Toast.makeText(MainActivity.this, "Connecting to " + input + "...", Toast.LENGTH_SHORT).show();
                loadWakeX();
            }
        });
        LinearLayout.LayoutParams connectParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        connectParams.setMargins(0, 0, 0, dpToPx(10));
        errorLayout.addView(connectBtn, connectParams);

        // Turn On PC Button (Direct Native Wake-on-LAN from Phone)
        Button turnOnBtn = new Button(this);
        turnOnBtn.setText("🚀 Turn On PC (Wake-on-LAN)");
        turnOnBtn.setTextColor(Color.parseColor("#FFFFFF"));
        turnOnBtn.setBackgroundColor(Color.parseColor("#10B981"));
        turnOnBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        turnOnBtn.setTypeface(null, Typeface.BOLD);
        turnOnBtn.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(12));
        LinearLayout.LayoutParams turnOnParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        turnOnParams.setMargins(0, 0, 0, dpToPx(10));
        turnOnBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendWakeOnLan(new String[]{"00-11-22-33-44-55", "00-AA-BB-CC-DD-EE"});
                Toast.makeText(MainActivity.this, "⚡ Turn On packets broadcasted! Waiting for PC...", Toast.LENGTH_LONG).show();
                errorLayout.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        loadWakeX();
                    }
                }, 5000);
            }
        });
        errorLayout.addView(turnOnBtn, turnOnParams);

        // Auto-Detect PC Button (Fast UDP Discovery + Subnet Probe Fallback)
        Button autoDetectBtn = new Button(this);
        autoDetectBtn.setText("🔍 Auto-Detect PC (UDP Beacon)");
        autoDetectBtn.setTextColor(Color.parseColor("#38BDF8"));
        autoDetectBtn.setBackgroundColor(Color.parseColor("#1E293B"));
        autoDetectBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        autoDetectBtn.setPadding(dpToPx(16), dpToPx(10), dpToPx(16), dpToPx(10));
        LinearLayout.LayoutParams autoParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        );
        autoParams.setMargins(0, 0, 0, dpToPx(10));
        autoDetectBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                scanSubnetForWakeX();
            }
        });
        errorLayout.addView(autoDetectBtn, autoParams);

        // Quick tip
        TextView tip = new TextView(this);
        tip.setText("Tap here to use default: 192.168.1.100:8000");
        tip.setTextColor(Color.parseColor("#06B6D4"));
        tip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        tip.setGravity(Gravity.CENTER);
        tip.setPadding(0, dpToPx(8), 0, 0);
        tip.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ipEditText.setText("192.168.1.100:8000");
                prefs.edit().putString(PREF_KEY_URL, "192.168.1.100:8000").apply();
                loadWakeX();
            }
        });
        errorLayout.addView(tip);
    }

    private String getLocalSubnetPrefix() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces != null) {
                for (NetworkInterface intf : Collections.list(interfaces)) {
                    if (intf.isLoopback() || !intf.isUp()) continue;
                    Enumeration<InetAddress> addrs = intf.getInetAddresses();
                    while (addrs.hasMoreElements()) {
                        InetAddress addr = addrs.nextElement();
                        if (!addr.isLoopbackAddress() && addr instanceof java.net.Inet4Address) {
                            String ip = addr.getHostAddress();
                            if (ip != null && ip.startsWith("192.168.")) {
                                int lastDot = ip.lastIndexOf('.');
                                if (lastDot > 0) {
                                    return ip.substring(0, lastDot + 1);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return "192.168.1.";
    }

    private void scanSubnetForWakeX() {
        Toast.makeText(this, "Searching Wi-Fi for WakeX PC...", Toast.LENGTH_SHORT).show();

        new Thread(new Runnable() {
            @Override
            public void run() {
                // 1. First attempt: Fast UDP discovery beacon on port 8002
                try {
                    DatagramSocket udpSocket = new DatagramSocket();
                    udpSocket.setBroadcast(true);
                    udpSocket.setSoTimeout(1200);

                    byte[] ping = "WAKEX_DISCOVER".getBytes("UTF-8");
                    InetAddress broadcastAddr = InetAddress.getByName("255.255.255.255");
                    DatagramPacket packet = new DatagramPacket(ping, ping.length, broadcastAddr, 8002);
                    udpSocket.send(packet);

                    byte[] buf = new byte[1024];
                    DatagramPacket resp = new DatagramPacket(buf, buf.length);
                    udpSocket.receive(resp);

                    String jsonStr = new String(resp.getData(), 0, resp.getLength(), "UTF-8");
                    JSONObject obj = new JSONObject(jsonStr);
                    final String discoveredIp = obj.getString("ip");
                    final int discoveredPort = obj.getInt("port");
                    final String hostTarget = discoveredIp + ":" + discoveredPort;

                    udpSocket.close();

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            ipEditText.setText(hostTarget);
                            prefs.edit().putString(PREF_KEY_URL, hostTarget).apply();
                            Toast.makeText(MainActivity.this, "⚡ Discovered PC at " + hostTarget + "!", Toast.LENGTH_LONG).show();
                            loadWakeX();
                        }
                    });
                    return;
                } catch (Exception ignored) {
                    // Fall back to subnet probing if UDP broadcast is dropped
                }

                // 2. Fallback: Quick probe on known IPs and active subnet
                final String subnetPrefix = getLocalSubnetPrefix();
                ExecutorService pool = Executors.newFixedThreadPool(32);
                final AtomicReference<String> found = new AtomicReference<>(null);

                String[] priorityIps = new String[]{"192.168.1.100", "192.168.1.50"};
                for (String pIp : priorityIps) {
                    try {
                        java.net.Socket s0 = new java.net.Socket();
                        s0.connect(new java.net.InetSocketAddress(pIp, 8000), 250);
                        s0.close();
                        found.set(pIp + ":8000");
                        break;
                    } catch (Exception ignored) {}
                }

                if (found.get() == null) {
                    for (int i = 1; i <= 254; i++) {
                        final String testIp = subnetPrefix + i;
                        pool.execute(new Runnable() {
                            @Override
                            public void run() {
                                if (found.get() != null) return;
                                try {
                                    java.net.Socket s = new java.net.Socket();
                                    s.connect(new java.net.InetSocketAddress(testIp, 8000), 300);
                                    s.close();
                                    found.set(testIp + ":8000");
                                } catch (Exception ignored) {}
                            }
                        });
                    }
                    pool.shutdown();
                    try {
                        pool.awaitTermination(2500, TimeUnit.MILLISECONDS);
                    } catch (Exception ignored) {}
                }

                final String result = found.get();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (result != null) {
                            ipEditText.setText(result);
                            prefs.edit().putString(PREF_KEY_URL, result).apply();
                            Toast.makeText(MainActivity.this, "Found WakeX PC at " + result + "!", Toast.LENGTH_LONG).show();
                            loadWakeX();
                        } else {
                            Toast.makeText(MainActivity.this, "Scan complete. If WakeX is running, enter IP manually.", Toast.LENGTH_LONG).show();
                        }
                    }
                });
            }
        }).start();
    }

    private volatile boolean isRebinding = false;

    private void autoRebindOnIpChange() {
        if (isRebinding) return;
        isRebinding = true;

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Step 1: Fast UDP Discovery probe on port 8002
                    DatagramSocket socket = new DatagramSocket();
                    socket.setBroadcast(true);
                    socket.setSoTimeout(1000);

                    byte[] ping = "WAKEX_DISCOVER".getBytes(StandardCharsets.UTF_8);
                    InetAddress globalBroadcast = InetAddress.getByName("255.255.255.255");
                    socket.send(new DatagramPacket(ping, ping.length, globalBroadcast, 8002));

                    String subPrefix = getLocalSubnetPrefix();
                    try {
                        InetAddress subBroadcast = InetAddress.getByName(subPrefix + "255");
                        socket.send(new DatagramPacket(ping, ping.length, subBroadcast, 8002));
                    } catch (Exception ignored) {}

                    byte[] buf = new byte[1024];
                    DatagramPacket resp = new DatagramPacket(buf, buf.length);
                    socket.receive(resp);
                    String jsonStr = new String(resp.getData(), 0, resp.getLength(), StandardCharsets.UTF_8);
                    JSONObject obj = new JSONObject(jsonStr);
                    final String discoveredIp = obj.getString("ip");
                    final int discoveredPort = obj.getInt("port");
                    final String newTarget = discoveredIp + ":" + discoveredPort;
                    socket.close();

                    String savedUrl = prefs.getString(PREF_KEY_URL, DEFAULT_URL).replace("http://", "").replace("https://", "");
                    if (!savedUrl.equals(newTarget)) {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                prefs.edit().putString(PREF_KEY_URL, newTarget).apply();
                                if (ipEditText != null) ipEditText.setText(newTarget);
                                Toast.makeText(MainActivity.this, "🔄 PC IP changed! Auto-rebound to " + newTarget, Toast.LENGTH_LONG).show();
                                loadWakeX();
                            }
                        });
                        isRebinding = false;
                        return;
                    }
                } catch (Exception ignored) {
                    // Fall back to quick /24 subnet probe
                }

                // Step 2: Fallback quick /24 subnet probe on port 8000
                final String subnetPrefix = getLocalSubnetPrefix();
                for (int i = 1; i <= 254; i++) {
                    final String testIp = subnetPrefix + i;
                    try {
                        java.net.Socket s = new java.net.Socket();
                        s.connect(new java.net.InetSocketAddress(testIp, 8000), 100);
                        s.close();
                        final String foundTarget = testIp + ":8000";
                        String savedUrl = prefs.getString(PREF_KEY_URL, DEFAULT_URL).replace("http://", "").replace("https://", "");
                        if (!savedUrl.equals(foundTarget)) {
                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    prefs.edit().putString(PREF_KEY_URL, foundTarget).apply();
                                    if (ipEditText != null) ipEditText.setText(foundTarget);
                                    Toast.makeText(MainActivity.this, "🔄 Auto-rebound to PC at " + foundTarget, Toast.LENGTH_LONG).show();
                                    loadWakeX();
                                }
                            });
                            isRebinding = false;
                            return;
                        }
                    } catch (Exception ignored) {}
                }
                isRebinding = false;
            }
        }).start();
    }

    private void showErrorScreen(String errorMsg) {
        updateNetworkBanner();
        String currentUrl = prefs.getString(PREF_KEY_URL, DEFAULT_URL);

        String diagnosticHint;
        if (!isConnectedToWifi()) {
            diagnosticHint = "⚠️ Phone is on Cellular Data. Connect to your home Wi-Fi network to reach your PC.";
        } else {
            diagnosticHint = "💡 If your PC is asleep or powered off, tap 'Turn On PC' below to send a Wake-on-LAN signal.\nSearching network for PC IP changes...";
            autoRebindOnIpChange();
        }

        errorUrlText.setText(errorMsg + "\nTarget: " + currentUrl + "\n\n" + diagnosticHint);
        ipEditText.setText(currentUrl.replace("http://", "").replace("https://", ""));
        errorLayout.setVisibility(View.VISIBLE);
        webView.setVisibility(View.GONE);
    }

    private void hideErrorScreen() {
        errorLayout.setVisibility(View.GONE);
        webView.setVisibility(View.VISIBLE);
    }

    private void loadWakeX() {
        watchdogHandler.removeCallbacks(timeoutRunnable);
        hideErrorScreen();
        pageLoadFailed = false;
        pageLoadSuccess = false;

        String url = prefs.getString(PREF_KEY_URL, DEFAULT_URL);
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        // Arm 6-second watchdog timer to avoid black screen hang
        watchdogHandler.postDelayed(timeoutRunnable, CONNECTION_TIMEOUT_MS);
        webView.loadUrl(url);
    }

    private void showServerUrlDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Configure WakeX Server");
        builder.setMessage("Enter your PC's IP address and port (e.g. 192.168.1.100:8000):");

        final EditText input = new EditText(this);
        input.setText(prefs.getString(PREF_KEY_URL, DEFAULT_URL).replace("http://", "").replace("https://", ""));
        input.setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(12));
        builder.setView(input);

        builder.setPositiveButton("Save & Connect", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String newUrl = input.getText().toString().trim();
                if (!newUrl.isEmpty()) {
                    prefs.edit().putString(PREF_KEY_URL, newUrl).apply();
                    Toast.makeText(MainActivity.this, "Connecting to " + newUrl, Toast.LENGTH_SHORT).show();
                    loadWakeX();
                }
            }
        });

        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private int dpToPx(int dp) {
        return (int) TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, dp, getResources().getDisplayMetrics()
        );
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    public void sendWakeOnLan(final String[] macAddresses) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String subnet = getLocalSubnetPrefix();
                    String dynamicBroadcast = subnet + "255";

                    for (String mac : macAddresses) {
                        if (mac == null || mac.trim().isEmpty()) continue;
                        String cleanMac = mac.replaceAll("[:\\-\\.]", "").toUpperCase(Locale.ROOT);
                        if (cleanMac.length() != 12) continue;

                        byte[] macBytes = new byte[6];
                        for (int i = 0; i < 6; i++) {
                            macBytes[i] = (byte) Integer.parseInt(cleanMac.substring(i * 2, i * 2 + 2), 16);
                        }

                        byte[] packetData = new byte[6 + 16 * 6];
                        for (int i = 0; i < 6; i++) packetData[i] = (byte) 0xFF;
                        for (int i = 0; i < 16; i++) {
                            System.arraycopy(macBytes, 0, packetData, 6 + i * 6, 6);
                        }

                        DatagramSocket socket = new DatagramSocket();
                        socket.setBroadcast(true);

                        String[] broadcastIps = new String[]{
                            "255.255.255.255",
                            "10.0.0.255",
                            "192.168.1.255",
                            dynamicBroadcast
                        };
                        int[] ports = new int[]{9, 7};

                        for (String bIp : broadcastIps) {
                            for (int port : ports) {
                                try {
                                    InetAddress address = InetAddress.getByName(bIp);
                                    DatagramPacket packet = new DatagramPacket(packetData, packetData.length, address, port);
                                    for (int burst = 0; burst < 3; burst++) {
                                        socket.send(packet);
                                        Thread.sleep(15);
                                    }
                                } catch (Exception ignored) {}
                            }
                        }
                        socket.close();
                    }
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this, "⚡ Turn On (Wake-on-LAN) sent from phone!", Toast.LENGTH_SHORT).show();
                        }
                    });
                } catch (final Exception e) {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(MainActivity.this, "WoL Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            }
        }).start();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (webView != null) {
            webView.onPause();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            webView.onResume();
        }
    }

    @Override
    protected void onDestroy() {
        if (watchdogHandler != null && timeoutRunnable != null) {
            watchdogHandler.removeCallbacks(timeoutRunnable);
        }
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
