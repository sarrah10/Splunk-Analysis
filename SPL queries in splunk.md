# Splunk Search Processing Language (SPL)

## Introduction
Splunk is a powerful SIEM solution that provides the ability to search and explore machine data.  
Search Processing Language (SPL) is used to make the search more effective. It consists of various commands and functions that can be combined to create optimized and efficient search queries.

---

## Search & Reporting App Overview
The Search & Reporting App is the default interface used to search and analyze data on the Splunk Home page. It provides multiple functionalities that assist analysts in improving the search experience.

---

## 1. Search Head
- The Search Head is where SPL queries are written and executed.
- Analysts use it to search, filter, and analyze indexed data.

---

## 2. Time Duration
- Allows selection of the time range for a search.
- Helps narrow down events to a specific timeframe.

Examples:
- All Time – Displays all available events
- Last 60 minutes – Displays events captured in the last hour

---

## 3. Search History
- Stores previously executed search queries.
- Displays the time when each search was run.
- Allows analysts to re-run and filter past searches.

---

## 4. Data Summary
- Provides a summary of:
  - Data sources
  - Sourcetypes
  - Hosts generating events
- Useful for gaining quick network visibility.

---

## 5. Field Sidebar
- Located on the left side of the Splunk search interface.
- Displays extracted fields from events.

### Field Sidebar Components
- Selected Fields
  - Default fields such as source, sourcetype, and host
- Interesting Fields
  - Dynamically extracted fields from events

### Field Indicators
- 'α' – Alphanumeric (text) fields
- '#' – Numeric fields
- Count – Number of events containing that field in the selected time range

---

## SPL Overview
SPL consists of operators, commands, and functions that allow analysts to filter, structure, and transform data efficiently.

---

## Search Field Operators

### Comparison Operators
- `=` Equal to
- `!=` Not equal to
- `<` Less than
- `<=` Less than or equal to
- `>` Greater than
- `>=` Greater than or equal to

### Example
```
index=windowslogs AccountName!=SYSTEM
```
---

## Boolean Operators
- AND – Matches all conditions
- OR – Matches any condition
- NOT – Excludes matching values

### Example
```
index=windowslogs AccountName!=SYSTEM AND AccountName=James
```

---

## Wildcards
- `*` is used to match partial strings.

### Example
```index=windowslogs DestinationIp=172.*```

---

## Filtering Results in SPL

### Fields Command
- Used to include or exclude fields from the output.

```index=windowslogs | fields + host + User + SourceIp```

---

### Search Command
- Used to search raw event text.

```index=windowslogs | search Powershell```

---

### Dedup Command
- Removes duplicate values based on a specific field.

```index=windowslogs | table EventID User Image Hostname | dedup EventID```

---

### Rename Command
- Renames fields in the search results.

```index=windowslogs | fields + host + User + SourceIp | rename User as Employees```

---

## Structuring Search Results

### Table Command
- Displays selected fields in a tabular format.

```index=windowslogs | table EventID Hostname SourceName```

---

### Head Command
- Displays the first N events from the result set.

```index=windowslogs | table _time EventID Hostname SourceName | head 5```

---

### Tail Command
- Displays the last N events from the result set.

```index=windowslogs | table _time EventID Hostname SourceName | tail 5```

---

### Sort Command
- Sorts results in ascending or descending order.

```index=windowslogs | table _time EventID Hostname SourceName | sort Hostname```

---

### Reverse Command
- Reverses the order of the search results.

```index=windowslogs | table _time EventID Hostname SourceName | reverse```

---

## Transformational Commands in SPL

### Top Command
- Displays the most frequent field values.

```index=windowslogs | top limit=7 Image```

---

### Rare Command
- Displays the least frequent field values.

```index=windowslogs | rare limit=7 Image```

---

### Highlight Command
- Highlights specific fields in raw event data.

```index=windowslogs | highlight User, host, EventID, Image```

---

## Stats Commands

### Common Statistical Functions
- Average
- Maximum
- Minimum
- Sum
- Count

### Examples
```
index=windowslogs | stats avg(product_price)
index=windowslogs | stats max(user_age)
index=windowslogs | stats min(product_price)
index=windowslogs | stats sum(product_cost)
index=windowslogs | stats count(Source_IP)
```

---

## Chart Commands

### Chart
- Transforms data into tables or visualizations.

```index=windowslogs | chart count by User```

---

### Timechart
- Displays time-based visualizations.

```index=windowslogs | timechart count by Image```

---

## Conclusion
This document covers core Splunk SPL concepts including searching, filtering, structuring, and transforming data. These commands form the foundation for SOC investigations, alert triage, and security monitoring workflows.

