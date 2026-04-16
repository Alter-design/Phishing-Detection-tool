# Phishing Detection Admin Fixes - TODO

## Plan Implementation Steps

### 1. [x] Update detector.py
- Add "Suspicious (Needs Verification)" logic in detect_url()
  - Legitimate + confidence <60 + rule_score <3 → Suspicious
  - Phishing + confidence <40 + rule_score==0 → Suspicious
- Update risk_level = 'MEDIUM'

### 2. [x] Update templates/admin.html
- Change confidence display to `{{ "%.1f"|format(scan[3]) }}%`
- Add styling for prediction == "Suspicious (Needs Verification)" with risk-medium class

### 3. [x] Test changes
- Run `python detector.py` and test uncertain URLs
- Restart app: `python app.py`
- Visit /admin, verify % display and Suspicious cases

### 4. [x] Complete
- Mark all done

Current progress: Starting step 1
