Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "."
WshShell.Run """%LOCALAPPDATA%\Python\bin\python.exe"" server.py", 0, False
Set WshShell = Nothing
