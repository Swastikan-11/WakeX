package com.wakex.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;
import java.util.Locale;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class WakeXTileService extends TileService {
    @Override
    public void onStartListening() {
        super.onStartListening();
        Tile tile = getQsTile();
        if (tile != null) {
            tile.setLabel("Wake PC");
            tile.setState(Tile.STATE_INACTIVE);
            tile.updateTile();
        }
    }

    @Override
    public void onClick() {
        super.onClick();
        Tile tile = getQsTile();
        if (tile != null) {
            tile.setState(Tile.STATE_ACTIVE);
            tile.updateTile();
        }

        SharedPreferences prefs = getSharedPreferences("WakeXPrefs", Context.MODE_PRIVATE);
        String macs = prefs.getString("wakex_device_macs", "00-AA-BB-CC-DD-EE,00-11-22-33-44-55");
        final String[] macList = macs.split(",");

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    for (String mac : macList) {
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

                // Reset tile state back to inactive after sending packets
                Tile t = getQsTile();
                if (t != null) {
                    t.setState(Tile.STATE_INACTIVE);
                    t.updateTile();
                }
            }
        }).start();

        Toast.makeText(this, "⚡ Turn On (Wake-on-LAN) signal sent to PC!", Toast.LENGTH_SHORT).show();
    }
}
