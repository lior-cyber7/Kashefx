"""Known global and regional (Middle East & Iraq) brands and their official domains."""

from typing import TypedDict


class BrandEntry(TypedDict):
    name: str
    aliases: list[str]
    domains: list[str]


BRANDS: list[BrandEntry] = [
    # Global brands
    {
        "name": "PayPal",
        "aliases": ["paypal"],
        "domains": ["paypal.com", "paypal.me"],
    },
    {
        "name": "Apple",
        "aliases": ["apple", "icloud"],
        "domains": ["apple.com", "icloud.com"],
    },
    {
        "name": "Google",
        "aliases": ["google", "gmail"],
        "domains": ["google.com", "gmail.com", "accounts.google.com"],
    },
    {
        "name": "Microsoft",
        "aliases": ["microsoft", "outlook", "office365"],
        "domains": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    },
    {
        "name": "Meta",
        "aliases": ["meta", "facebook", "instagram"],
        "domains": ["meta.com", "facebook.com", "instagram.com", "fb.com"],
    },
    {
        "name": "Netflix",
        "aliases": ["netflix"],
        "domains": ["netflix.com"],
    },
    {
        "name": "DHL",
        "aliases": ["dhl"],
        "domains": ["dhl.com", "dhl.de"],
    },
    {
        "name": "Amazon",
        "aliases": ["amazon"],
        "domains": ["amazon.com", "amazon.ae", "amazon.sa"],
    },
    {
        "name": "WhatsApp",
        "aliases": ["whatsapp"],
        "domains": ["whatsapp.com", "wa.me"],
    },
    {
        "name": "Telegram",
        "aliases": ["telegram"],
        "domains": ["telegram.org", "t.me"],
    },
    {
        "name": "Binance",
        "aliases": ["binance"],
        "domains": ["binance.com"],
    },
    {
        "name": "Visa",
        "aliases": ["visa"],
        "domains": ["visa.com"],
    },
    # Regional Middle East & Iraq-relevant brands
    {
        "name": "Zain",
        "aliases": ["zain", "zainiq"],
        "domains": ["zain.com", "iq.zain.com", "sa.zain.com"],
    },
    {
        "name": "Asiacell",
        "aliases": ["asiacell"],
        "domains": ["asiacell.com"],
    },
    {
        "name": "Korek",
        "aliases": ["korek", "korektel"],
        "domains": ["korektel.com"],
    },
    {
        "name": "ZainCash",
        "aliases": ["zaincash"],
        "domains": ["zaincash.iq"],
    },
    {
        "name": "FastPay",
        "aliases": ["fastpay"],
        "domains": ["fast-pay.cash", "fastpay.iq"],
    },
    {
        "name": "AsiaPay",
        "aliases": ["asiapay"],
        "domains": ["asiapay.iq"],
    },
    {
        "name": "NassWallet",
        "aliases": ["nasswallet"],
        "domains": ["nasswallet.com"],
    },
    {
        "name": "Rafidain Bank",
        "aliases": ["rafidain", "rafidainbank"],
        "domains": ["rafidain-bank.gov.iq", "rafidainbank.iq"],
    },
    {
        "name": "Rasheed Bank",
        "aliases": ["rasheed", "rasheedbank"],
        "domains": ["rasheedbank.gov.iq"],
    },
    {
        "name": "Trade Bank of Iraq (TBI)",
        "aliases": ["tbi", "tbiraq"],
        "domains": ["tbi.com.iq"],
    },
    {
        "name": "Qi Card",
        "aliases": ["qicard", "qi"],
        "domains": ["qi.iq", "qicard.com"],
    },
    {
        "name": "MasterCard Iraq",
        "aliases": ["mastercard", "mastercardiq"],
        "domains": ["mastercard.com", "altareq.iq"],
    },
    {
        "name": "Iraqi Post",
        "aliases": ["iraqipost", "iqpost"],
        "domains": ["iraqipost.gov.iq", "moc.gov.iq"],
    },
    {
        "name": "Toters",
        "aliases": ["toters"],
        "domains": ["totersapp.com"],
    },
    {
        "name": "Talabatey",
        "aliases": ["talabatey"],
        "domains": ["talabatey.com"],
    },
]
