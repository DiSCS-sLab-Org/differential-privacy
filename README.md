# Differential Privacy Attack Query System

Web dashboard for querying attack counts by day with differential privacy protection.

## 🎯 Purpose

Protects IP address information when querying: **"Give me the number of attacks on day X"**

**Problem**: If someone knows IP address XYZ sent many attacks, returning the exact count reveals which day XYZ attacked.

**Solution**: Differential Privacy adds Laplace noise proportional to the largest attacker's contribution, hiding any single IP's presence.

## 🔒 How It Works

Simple flow for every query:
1. User enters date (e.g., 2025-01-15)
2. System fetches that day's attack data from Elasticsearch
3. Calculates sensitivity (max attacks from any single IP)
4. Adds Laplace noise: `noise ~ Laplace(0, sensitivity/ε)`
5. Returns noisy count

**Every query is independent:**
- Same day queried twice → Fresh data fetch + Fresh noise = Different results
- Different day → Fetches new day's data + Calculates + Returns noisy count

**No caching. No pre-fetching. No storage.**

## 📦 Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## 🖥️ Usage

### Normal Mode (Production - Clean Results Only)
```bash
python3 app.py
```
Shows only the DP-protected result - clean and simple!

### Debug Mode (For Development/Testing)
```bash
python3 app.py -d
```
Shows additional details: sensitivity, noise, true count, top attackers, interpretation.

### Accessing the Dashboard

When you start the app, it will display access URLs:

**On the same machine:**
```
http://localhost:8889
```

**From other machines on local network:**
```
http://<vm-hostname>:8889
```
Replace `<vm-hostname>` with your VM's hostname (shown when app starts)

**Then:**
1. **Enter date**: Select date from calendar
2. **Adjust epsilon**: Slide to set privacy level (0.5-1.0 recommended)
3. **Query**: Click "Query Attack Count"
4. **Repeat**: Try querying the same day multiple times - see different results!

## 🔧 Files

| File | Purpose |
|------|---------|
| `app.py` | Flask web application - **RUN THIS** |
| `fetch_day_attacks.py` | Fetch module (imported by app) |
| `templates/index.html` | Web dashboard interface |
| `requirements.txt` | Python dependencies |

## 🎛️ Parameters

### Epsilon (ε) - Privacy Budget

| Range | Privacy Level | Noise Amount |
|-------|---------------|--------------|
| 0.1-0.5 | Very Strong | Very high noise |
| **0.5-1.0** | **Strong (recommended)** | **High noise** |
| 1.0-2.0 | Moderate | Medium noise |
| 2.0-5.0 | Weak | Low noise |

### Sensitivity (Δf) - Auto-calculated

- Maximum attacks from any single IP on that day
- Determines the scale of noise added
- Noise scale = Sensitivity / Epsilon

## 📊 Example

**Day 2025-01-15**: 700 total attacks, largest attacker sent 500 attacks

**Query 3 times with ε=1.0:**

```
Query 1: 823 attacks  (noise: +123)
Query 2: 612 attacks  (noise: -88)  ← Different!
Query 3: 759 attacks  (noise: +59)  ← Different again!
```

**Query different day (2025-01-16):**
- Fetches 2025-01-16 data
- Calculates new sensitivity for that day
- Returns noisy count

## 🛡️ Why This Protects Privacy

Even if an attacker knows their IP sent 500 attacks:
- Cannot determine which day from the noisy result
- Noise magnitude (~500 with ε=1.0) is comparable to their contribution
- Each query gives a different result (fresh noise)
- Their presence or absence is hidden in the noise

## ⚙️ Configuration

Edit Elasticsearch settings in `fetch_day_attacks.py`:

```python
ES_CONFIG = {
    "host": "https://your-elasticsearch:9200",
    "api_key": "your-api-key-here",
    ...
}
```

## 🧪 Testing

Test the fetch module independently:

```bash
python3 fetch_day_attacks.py 2025-01-15
```

This will fetch and display data for the specified day (useful for debugging).
# differential-privacy
