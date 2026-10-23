package com.wakex.app;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.widget.RemoteViews;
import android.widget.Toast;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class WakeXAppWidgetProvider extends AppWidgetProvider {
    public static final String ACTION_WAKE_PC = "com.wakex.app.ACTION_WAKE_PC";

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        for (int appWidgetId : appWidgetIds) {
            updateAppWidget(context, appWidgetManager, appWidgetId);
        }
    }

    private static void updateAppWidget(Context context, AppWidgetManager appWidgetManager, int appWidgetId) {
        RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget_wakex);

        // 1. Wake PC Button
        Intent wakeIntent = new Intent(context, WakeXAppWidgetProvider.class);
        wakeIntent.setAction(ACTION_WAKE_PC);
        PendingIntent wakePendingIntent = PendingIntent.getBroadcast(
                context, 0, wakeIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        views.setOnClickPendingIntent(R.id.widget_btn_wake, wakePendingIntent);

        // 2. Open WakeX App Button
        Intent appIntent = new Intent(context, MainActivity.class);
        PendingIntent appPendingIntent = PendingIntent.getActivity(
                context, 1, appIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        views.setOnClickPendingIntent(R.id.widget_btn_app, appPendingIntent);

        appWidgetManager.updateAppWidget(appWidgetId, views);
    }

    @Override
    public void onReceive(final Context context, Intent intent) {
        super.onReceive(context, intent);

        if (ACTION_WAKE_PC.equals(intent.getAction())) {
            SharedPreferences prefs = context.getSharedPreferences("WakeXPrefs", Context.MODE_PRIVATE);
            String macs = prefs.getString("wakex_device_macs", "00-AA-BB-CC-DD-EE,00-11-22-33-44-55");
            final String[] macList = macs.split(",");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (String mac : macList) {
                            String cleanMac = mac.replaceAll("[:\\-\\.]", "").toUpperCase();
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

                            String[] broadcasts = new String[]{"255.255.255.255", "192.168.1.255", "192.168.1.255"};
                            for (String bIp : broadcasts) {
                                for (int port : new int[]{9, 7}) {
                                    try {
                                        InetAddress addr = InetAddress.getByName(bIp);
                                        DatagramPacket packet = new DatagramPacket(packetData, packetData.length, addr, port);
                                        for (int b = 0; b < 3; b++) {
                                            socket.send(packet);
                                            Thread.sleep(10);
                                        }
                                    } catch (Exception ignored) {}
                                }
                            }
                            socket.close();
                        }
                    } catch (Exception ignored) {}
                }
            }).start();

            Toast.makeText(context, "⚡ Wake-on-LAN Magic Packet sent to PC!", Toast.LENGTH_SHORT).show();
        }
    }
}
