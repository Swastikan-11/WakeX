"""
AetherCommand In-App Interactive Assistant & Command Bot
Processes natural language commands, reports system state, triggers multi-device actions.
"""
import re
import datetime
from engine import telemetry, power, workspace, scheduler, devices

class BotAssistant:
    def __init__(self):
        self.history = [
            {
                "sender": "bot",
                "text": "👋 Hello! I am your PC Assistant. Ask me about system health, wake schedules, tell me to turn on devices, or manage power.",
                "timestamp": datetime.datetime.now().strftime("%H:%M")
            }
        ]

    def process_message(self, user_text: str) -> dict:
        text = user_text.lower().strip()
        timestamp = datetime.datetime.now().strftime("%H:%M")
        
        # Save user message to history
        self.history.append({"sender": "user", "text": user_text, "timestamp": timestamp})
        
        reply = ""
        action_triggered = None
        data = None

        # 1. Turn On / Wake Device (Wake-on-LAN)
        if "turn on" in text or "switch on" in text or "wake pc" in text or "wake" in text and "schedule" not in text and "time" not in text:
            dev_list = devices.load_devices()
            target = None
            for d in dev_list:
                if d["name"].lower() in text or d["id"].lower() in text:
                    target = d
                    break
            if not target and dev_list:
                target = dev_list[0]
            
            if target and target.get("mac"):
                res = devices.send_wake_on_lan(target["mac"])
                reply = f"⚡ **Turn On command sent!** Broadcasted Magic Packet to **{target['name']}** (MAC: {target['mac']})."
                action_triggered = "device_woken"
            else:
                reply = "⚠️ Could not find a target device with a configured MAC address to turn on."

        # 2. List Paired Devices
        elif "devices" in text or "list devices" in text or "paired" in text:
            dev_list = devices.load_devices()
            lines = [f"• **{d['name']}** (`{d.get('ip')}`) - MAC: `{d.get('mac')}` [{'Host' if d.get('is_current') else 'Remote'}]" for d in dev_list]
            reply = "🖥️ **Paired Devices:**\n" + "\n".join(lines)

        # 3. Battery & Power Telemetry
        elif "battery" in text or "charge" in text or "power" in text and "off" not in text and "down" not in text:
            stats = telemetry.get_system_telemetry()
            plugged = "Plugged in (Charging/AC)" if stats.get("power_plugged") else "Running on Battery"
            pct = stats.get("battery_percent")
            reply = f"🔋 Battery is at **{pct}%** ({plugged})."

        # 4. System Status / Metrics
        elif "status" in text or "stats" in text or "cpu" in text or "ram" in text or "memory" in text:
            stats = telemetry.get_system_telemetry()
            reply = (
                f"💻 **System Status:**\n"
                f"• CPU Load: **{stats.get('cpu_percent')}%**\n"
                f"• RAM Usage: **{stats.get('memory_percent')}%** ({stats.get('memory_used_gb')}GB / {stats.get('memory_total_gb')}GB)\n"
                f"• Uptime: **{stats.get('uptime')}**\n"
                f"• Battery: **{stats.get('battery_percent')}%**"
            )

        # 5. Screen Snapshot
        elif "screen" in text or "snapshot" in text or "screenshot" in text:
            reply = "📸 Captured current screen snapshot. Displaying preview below."
            action_triggered = "refresh_screen"

        # 6. Wake Schedule Query
        elif "wake schedule" in text or "schedule" in text or "shift time" in text:
            wake_info = scheduler.get_wake_status()
            if wake_info.get("enabled"):
                days = ", ".join(wake_info.get("days", []))
                reply = f"⏰ Next scheduled hardware wake is at **{wake_info.get('time')}** on **{days}**."
            else:
                reply = "⏰ Wake schedule is currently **Disabled**. You can enable it in the Schedule tab."

        # 7. Workspace Launch Command
        elif "launch" in text or "start" in text or "open workspace" in text:
            workspaces = workspace.load_workspaces()
            target_profile = None
            for p in workspaces.get("profiles", []):
                if p["id"] in text or p["name"].lower() in text:
                    target_profile = p["id"]
                    break
            
            if not target_profile:
                target_profile = workspaces.get("active_profile", "work_shift")

            res = workspace.launch_workspace(target_profile)
            if res.get("status") == "success":
                apps = ", ".join(res.get("launched_apps", [])) or "None"
                urls_count = len(res.get("launched_urls", []))
                reply = f"🚀 Launched workspace **{res.get('profile_name')}** ({urls_count} browser tabs opened, apps: {apps})."
                action_triggered = "workspace_launched"
            else:
                reply = f"⚠️ Could not launch workspace: {res.get('message')}"

        # 8. Unlock Screen
        elif "unlock" in text or "wake screen" in text:
            reply = "🔓 Awakening display and dismissing lock screen..."
            action_triggered = "unlock"
            power.trigger_unlock()

        # 9. Lock Workstation
        elif "lock" in text:
            reply = "🔒 Workstation session locked."
            action_triggered = "lock"
            power.trigger_lock()

        # 10. Hibernate
        elif "hibernate" in text:
            reply = "💤 Initiating 0-Watt Hibernate state... Goodbye!"
            action_triggered = "hibernate"
            power.trigger_hibernate()

        # 11. Sleep
        elif "sleep" in text:
            reply = "🌙 Entering low-power sleep mode..."
            action_triggered = "sleep"
            power.trigger_sleep()


        # 10. Restart
        elif "restart" in text or "reboot" in text:
            reply = "🔄 Restarting the PC in 5 seconds..."
            action_triggered = "restart"
            power.trigger_restart(delay_seconds=5)

        # 11. Shutdown
        elif "shutdown" in text or "turn off" in text:
            reply = "🛑 Shutting down the PC in 5 seconds..."
            action_triggered = "shutdown"
            power.trigger_shutdown(delay_seconds=5)

        # 12. Help / Fallback
        else:
            reply = (
                "🤖 I can help you with:\n"
                "• *'Turn on PC'* - Send Wake-on-LAN packet\n"
                "• *'Devices'* - View all paired computers\n"
                "• *'Status'* - View CPU, RAM, & Battery\n"
                "• *'Screenshot'* - Grab desktop screen preview\n"
                "• *'Launch Work Shift'* - Open work apps\n"
                "• *'Hibernate' / 'Sleep'* - Power down safely"
            )

        bot_entry = {
            "sender": "bot",
            "text": reply,
            "timestamp": timestamp,
            "action": action_triggered,
            "data": data
        }
        self.history.append(bot_entry)
        
        # Keep history compact (last 50 messages)
        if len(self.history) > 50:
            self.history = self.history[-50:]

        return bot_entry

bot_instance = BotAssistant()
