# Aggy - Shodan Webhook Aggregator

## TL;DR
This listens on port 5963 by default and listens for shodan webhooks, then outputs what it receives into a csv file.
You can also throw shodan alert output at this, but you can just use shodan CLI to convert alert data to a CSV. ¯\\_(ツ)_/¯

## Config
Set which IP to bind to, and what port to listen on in config.ini. 

## Usage
Source the venv, start listener.py
Congratulations, you started a python program. Go grab a glass of water if you can.

## Output
This program outputs data to one of two files:
- Open Databases:   _data/[%Y-W%V]_open_dbs.csv_ 
- Everything Else that you'd want to verify with a vuln scan: _data/[%Y-W%V]_assets_to_scan.csv_ 
- (If you're not familiar with the date format, each file of findings is grouped by each week of the year: 2023_51_assets_to_scan.csv if it's the 51st week of the year 2023)

## Logging
Request Logging
- Request metadata is logged to shodan_webhook_listener.log
- Log Levels:
  - INFO: Host that is sending requests
  - DEBUG: Request json, Host that is sending requests