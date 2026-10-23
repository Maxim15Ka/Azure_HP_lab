# Azure Cowrie Honeypot and Microsoft Sentinel Lab

I deployed a Cowrie SSH honeypot on an Azure Ubuntu VM, collected its JSON telemetry with Azure Monitor Agent, and used Microsoft Sentinel to investigate activity, visualize source IP locations, and generate an incident through a scheduled detection rule.

The final export contains **4,301 SSH connection events from six source IP addresses**, with **4,290 accepted honeypot logins, one failed login, and 4,290 command-input events**. These counts describe recorded activity; they are not counts of unique attackers or compromised systems.

## Architecture

```text
SSH client -> Cowrie (TCP 2222) -> cowrie.json
                                    |
                            Azure Monitor Agent
                                    |
                      Data Collection Rule (Linux)
                                    |
                  Log Analytics workspace / Cowrie_CL
                                    |
                        Microsoft Sentinel
                     /              |             \
             KQL investigation   Map workbook   Analytics rule
                                                    |
                                              Alert + incident
```

## Tools and configuration

- Azure Ubuntu VM: `Cyber-net`
- Cowrie with a dedicated Linux account and Python virtual environment
- SSH for administration and XRDP for graphical access
- UFW and Azure network access rules
- Log Analytics workspace: `law-cowrie-lab`
- Custom Analytics table: `Cowrie_CL`
- Data Collection Rule: `dcr-cowrie-lab`
- Source file: `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`
- Kusto Query Language (KQL), Microsoft Sentinel analytics, entity mapping, and workbooks

## Implementation and troubleshooting

1. **Established VM access.** OpenSSH initially rejected my private key because its Windows file permissions were too permissive. I adjusted the permissions with `icacls` and successfully connected.
2. **Deployed Cowrie.** I worked through missing launcher/configuration paths and Python package discovery errors. Startup logs subsequently confirmed that Cowrie was listening on TCP 2222.
3. **Validated local recording.** I connected to Cowrie locally and entered `whoami`, `pwd`, `ls`, and `exit`. JSON events confirmed session, login, and command capture. Loopback tests were excluded from the final summary.
4. **Enabled graphical administration.** I verified XRDP service status and its listening socket, resolved firewall access issues, and confirmed a successful desktop login.
5. **Configured centralized collection.** I created the workspace, enabled Sentinel, provisioned `Cowrie_CL`, and associated the VM with a Custom JSON Logs collection rule. The configured columns excluded the password and message fields.
6. **Analyzed and visualized activity.** I queried connection, login, and command events and enriched source addresses with `geo_info_from_ip_address()` for a workbook map.
7. **Validated detection.** I enabled a scheduled rule for at least 20 connection events from one IP within five minutes, mapped `src_ip` to an IP entity, and confirmed incident creation.

## Observation period and results

The final CSV has a report cutoff of **October 15, 2026, 04:34:13.465 UTC** (12:34:13 a.m. EDT). The earliest recorded external-source event is **02:13:00.278 UTC**, and the latest is **04:32:59.387 UTC**. Recorded activity therefore spans approximately **2 hours 20 minutes**. These are observed event boundaries, not proof of the VM's exact startup time.

| Source IP | Connections | Accepted logins | Failed logins | Command inputs |
|---|---:|---:|---:|---:|
| 8.134.58.87 | 4,292 | 4,290 | 1 | 4,290 |
| 40.124.179.77 | 2 | 0 | 0 | 0 |
| 43.226.60.99 | 2 | 0 | 0 | 0 |
| 89.248.171.24 | 2 | 0 | 0 | 0 |
| 195.96.139.132 | 2 | 0 | 0 | 0 |
| 89.248.172.12 | 1 | 0 | 0 | 0 |
| **Total** | **4,301** | **4,290** | **1** | **4,290** |

Source: [final observation summary](data/observation-summary.csv). The dominant IP accounts for approximately **99.8%** of connection events. A connection does not necessarily progress to authentication or command input, and the event totals need not match one another.

## Investigation

Saved session results show repeated short connections from `8.134.58.87`, login as `root` in Cowrie, submission of a command, and disconnection. One observed command was:

```bash
echo -e "\x6F\x6B"
```

This prints `ok`, consistent with checking shell responsiveness. Repetition suggests automated probing, but the available evidence does not identify the operator. An accepted login is into Cowrie's simulated environment and does not establish root access to the underlying Ubuntu VM.

The five other sources have connection events but no login or command events in the export. Their intent cannot be established from this summary alone.

### Follow-up command pattern analysis

After the original export, I ran a rolling 24-hour query grouping command-input events from `8.134.58.87` by their `input` value. The returned results contained **4,476 command-input events**, all with the same command:

```bash
echo -e "\x6F\x6B"
```

The hexadecimal values represent the letters `o` and `k`, so this command prints `ok`. Combined with the repeated connect, login, command, and disconnect sequence, this strongly suggests an automated check for a responsive shell.

This finding explains the dominant source's repetitive command activity. The command alone does not establish malware execution, host compromise, the operator's identity, or their broader purpose.

The **4,476** count comes from a later query with a different cutoff than the original CSV. It is reported separately and is not added to the original **4,290** command-input total. The follow-up count was supplied from the query results; a separate export or screenshot is not included in this package. The query is saved in [command-patterns.kql](queries/command-patterns.kql).

## Geographic visualization

### Completed workbook: map and source-location table

I added a source-location table below the connection map to display readable IP addresses, approximate locations, and connection counts alongside the geographic view.

![Completed Cowrie workbook with a connection map and source-location table](images/workbook-map-and-source-table.png)

The table visible in this later screenshot reports:

| Source IP | Approximate location | Connections |
|---|---|---:|
| 8.134.58.87 | Guangzhou, China | 4,663 |
| 40.124.179.77 | San Antonio, United States | 2 |
| 43.226.60.99 | China; city unavailable | 2 |
| 89.248.171.24 | The Netherlands; city unavailable | 2 |
| 195.96.139.132 | United Kingdom; city unavailable | 2 |
| 89.248.172.12 | Utrecht, The Netherlands | 1 |
| **Visible table total** | **Six source IPs across four countries** | **4,672** |

The map in the same screenshot displays approximately **4.76K** connections for the dominant source and seven source labels, while the table displays **4,663** for that source and six rows. The components therefore represent different result snapshots; their counts are not combined or treated as synchronized. The screenshot does not establish a shared query window or refresh cutoff for both components. The exported observation summary above remains the source for the fixed-cutoff totals.

The workbook's upper counters display approximately **37.6K Cowrie_CL rows**, **153 Heartbeat rows**, **27 SecurityIncident rows**, **26 SecurityAlert rows**, and **8 Usage rows**. These are table-record counts for that component's scope, not verified counts of unique attacks, incidents, or alerts.

### Earlier workbook evidence

![Workbook showing source IP locations and connection activity](images/connection-map.png)

This screenshot is an earlier rolling-window snapshot, not the final observation totals. The earlier map CSV contains four source IPs and 1,814 connections; it must not be combined with the final CSV as additional activity.

The map lookup associated the dominant source with Guangzhou, while Sentinel entity enrichment displayed Hangzhou. Geographic enrichment is approximate and can vary by dataset. It does not establish an operator's physical location.

The starter workbook's table counters count log rows. They should not be interpreted as unique attacks, alerts, or incidents.

## Detection validation

| Setting | Value |
|---|---|
| Rule | Cowrie - Repeated SSH Connections |
| Threshold | At least 20 connection events per source IP |
| Lookback / frequency | 5 minutes / 5 minutes |
| Alert result threshold | Greater than 0 matching rows |
| Severity | Low |
| Entity | IP Address mapped to `src_ip` |
| Incident creation | Enabled |

The rule produced **incident #2**, containing one alert and the mapped IP `8.134.58.87`. This verifies the path from captured activity to a Sentinel incident. The threshold was chosen for the lab and would require tuning in another environment.

![Sentinel incident with the mapped source IP](images/sentinel-incident.png)

## Skills demonstrated and limitations

This project demonstrates Linux and Azure administration, application troubleshooting, custom log ingestion, KQL investigation, geographic visualization, and scheduled detection validation. It demonstrates monitoring and detection; it does not establish host compromise, attribution, automated containment, or full incident response.

The final totals reflect records available at export time. Late-arriving logs and any uncollected events are outside those totals. No final deallocation or resource deletion is asserted in this report.

## Credits

Inspired by [Josh Madakor's Azure SOC tutorial](https://www.youtube.com/watch?v=g5JL2RIbThM), adapted to an Ubuntu/Cowrie implementation. I used Gemini and Codex for setup and troubleshooting guidance. Reported outcomes are supported by my exported results and screenshots.
