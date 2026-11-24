@echo off
title Lightweight NIDS Launcher
cd /d "%~dp0"
echo [*] Installing required libraries...
pip install streamlit pandas scapy --quiet
echo [*] Starting Lightweight NIDS...
streamlit run app.py
pause