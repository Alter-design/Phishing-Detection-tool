import pandas as pd

phishing_urls = [
    "http://paypal-login-secure.xyz",
    "http://maybank-verify-account.top",
    "http://secure-facebook-login.ru",
    "http://shopee-free-voucher.win",
    "http://update-bank-account-confirm.info",
    "http://bit.ly/secure-login-now",
    "http://192.168.0.1/verify",
    "http://account-security-alert.xyz"
]

legit_urls = [
    "https://google.com",
    "https://youtube.com",
    "https://github.com",
    "https://maybank2u.com.my",
    "https://shopee.com.my",
    "https://lazada.com.my",
    "https://facebook.com",
    "https://openai.com",
    "https://www.uptm.edu.my"
]

data = []

for url in phishing_urls:
    data.append([url, "phishing"])

for url in legit_urls:
    data.append([url, "legit"])

df = pd.DataFrame(data, columns=["url", "label"])

df.to_csv("modern_dataset.csv", index=False)

print("✅ Modern dataset created!")