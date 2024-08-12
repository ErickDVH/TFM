import requests
import whois
import socket
import ssl
from bs4 import BeautifulSoup
import time
import random
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Inicializa colorama
init(autoreset=True)

# Función para buscar en Google usando SerpApi
def buscar_en_google_serpapi(consulta, api_key):
    params = {
        "engine": "google",
        "q": consulta,
        "api_key": api_key
    }
    try:
        response = requests.get("https://serpapi.com/search", params=params)
        if response.status_code == 200:
            json_response = response.json()
            if 'organic_results' in json_response:
                results = json_response['organic_results']
                links = [result.get("link") for result in results if "link" in result]
                return links
            else:
                print("No se encontraron resultados orgánicos en la respuesta.")
                return []
        else:
            print(f"Error al buscar en Google usando SerpApi: {response.status_code}")
            print(f"Mensaje: {response.text}")
            return []
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return []

# Función para buscar subdominios usando crt.sh
def buscar_subdominios(dominio):
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{dominio}&output=json")
        if response.status_code == 200:
            subdomains = set(entry['name_value'] for entry in response.json())
            return subdomains
        else:
            print("Error al buscar subdominios en crt.sh.")
            return set()
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return set()

# Función para analizar registros DNS
def analizar_dns(dominio):
    try:
        respuesta_dns = socket.gethostbyname_ex(dominio)
        if respuesta_dns[2]:
            return {'Tipo de registro': respuesta_dns[0], 'Datos': respuesta_dns[2]}
        else:
            print("No se encontraron registros DNS para el dominio:", dominio)
            return None
    except socket.gaierror as e:
        print("Error al resolver el dominio:", e)
        return None

# Función para obtener información WHOIS
def analizar_whois(dominio):
    try:
        info_whois = whois.whois(dominio)
        return info_whois
    except Exception as e:
        print("Error al obtener información WHOIS:", e)
        return None

# Función para obtener certificados SSL
def certificados_ssl(dominio):
    try:
        contexto_ssl = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with contexto_ssl.wrap_socket(sock, server_hostname=dominio) as ssock:
                certificado = ssock.getpeercert()
                return certificado
    except Exception as e:
        print("Error al buscar certificados SSL:", e)
        return None

# Función para obtener enlaces de una página web usando BeautifulSoup
def obtener_enlaces_pagina(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            enlaces = set(a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http'))
            return enlaces
        else:
            print(f"Error al acceder a {url}: {response.status_code}")
            return set()
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return set()

# Función para obtener enlaces de Wayback Machine usando parámetros sugeridos
def obtener_enlaces_wayback(dominio):
    enlaces_wayback = set()
    try:
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url={dominio}")
        if response.status_code == 200:
            resultados = response.json()
            for resultado in resultados[1:]:
                enlaces_wayback.add(resultado[0])
        else:
            print("Error al buscar en Wayback Machine.")
    except requests.RequestException as e:
        print("Error de conexión:", e)
    return enlaces_wayback

# Función para verificar si un enlace es un dominio válido
def es_dominio_valido(enlace):
    try:
        dominio = urlparse(enlace).netloc
        return dominio if dominio else None
    except Exception:
        return None

# Función para obtener enlaces externos de Wayback Machine
def obtener_enlaces_externos_wayback(dominio):
    urls_wayback = obtener_enlaces_wayback(dominio)
    enlaces_externos = set()
    for url in urls_wayback:
        print(f"Analizando {url} desde Wayback Machine...")
        enlaces_pagina = obtener_enlaces_pagina(url)
        for enlace in enlaces_pagina:
            dominio_enlace = es_dominio_valido(enlace)
            if dominio != dominio_enlace and dominio_enlace:
                enlaces_externos.add(dominio_enlace)
        time.sleep(random.uniform(1, 3))  # Añade un pequeño retraso entre solicitudes
    return enlaces_externos

# Función para obtener enlaces de redes sociales
def obtener_enlaces_redes_sociales(dominio, api_key):
    social_links = set()
    redes_sociales = ["twitter.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com"]

    for red in redes_sociales:
        print(f"Buscando en {red} para {dominio}...")
        consulta = f"site:{red} {dominio}"
        links = buscar_en_google_serpapi(consulta, api_key)
        if links:
            social_links.update(links)
        time.sleep(random.uniform(1, 3))  # Añade un pequeño retraso entre solicitudes para evitar problemas de tasa de peticiones

    return social_links

# Función para recopilar y correlacionar datos del dominio
def recopilar_y_correlacionar_datos(dominio, api_key):
    resultados_google = buscar_en_google_serpapi(dominio, api_key)
    subdominios = buscar_subdominios(dominio)
    respuesta_dns = analizar_dns(dominio)
    info_whois = analizar_whois(dominio)
    certificado = certificados_ssl(dominio)
    enlaces_externos_wayback = obtener_enlaces_externos_wayback(dominio)
    enlaces_redes_sociales = obtener_enlaces_redes_sociales(dominio, api_key)

    datos_dominio = {
        'Resultados Google': resultados_google,
        'Subdominios': subdominios,
        'Registros DNS': respuesta_dns,
        'Información WHOIS': info_whois,
        'Certificado SSL/TLS': certificado,
        'Enlaces Externos Wayback': enlaces_externos_wayback,
        'Enlaces Redes Sociales': enlaces_redes_sociales
    }

    return datos_dominio

# Función para encontrar dominios relacionados
def encontrar_dominios_relacionados(dominio_principal, api_key):
    resultados_google = buscar_en_google_serpapi(dominio_principal, api_key)
    dominios_relacionados = set()

    # Obtiene dominios desde resultados de búsqueda en Google
    for result in resultados_google:
        dominio_rel = es_dominio_valido(result)
        if dominio_rel and dominio_principal not in dominio_rel:
            dominios_relacionados.add(dominio_rel)

    # Obtiene dominios desde enlaces externos de Wayback Machine
    enlaces_externos_wayback = obtener_enlaces_externos_wayback(dominio_principal)
    for dominio_rel in enlaces_externos_wayback:
        if dominio_principal not in dominio_rel:
            dominios_relacionados.add(dominio_rel)

    # Obtiene dominios desde redes sociales
    enlaces_redes_sociales = obtener_enlaces_redes_sociales(dominio_principal, api_key)
    for enlace in enlaces_redes_sociales:
        dominio_rel = es_dominio_valido(enlace)
        if dominio_principal not in dominio_rel:
            dominios_relacionados.add(dominio_rel)

    return dominios_relacionados

# Función para comparar dominios
def comparar_dominios(dominio1, dominio2):
    print(f"{Fore.BLUE}Comparación de la información WHOIS:{Style.RESET_ALL}")
    if dominio1['Información WHOIS'] and dominio2['Información WHOIS']:
        for key in dominio1['Información WHOIS']:
            if key in dominio2['Información WHOIS']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 1: {dominio1['Información WHOIS'][key]}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 2: {dominio2['Información WHOIS'][key]}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Comparación de registros DNS:{Style.RESET_ALL}")
    if dominio1['Registros DNS'] and dominio2['Registros DNS']:
        for key in dominio1['Registros DNS']:
            if key in dominio2['Registros DNS']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 1: {dominio1['Registros DNS'][key]}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 2: {dominio2['Registros DNS'][key]}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Comparación de enlaces externos en Wayback Machine:{Style.RESET_ALL}")
    if dominio1['Enlaces Externos Wayback'] and dominio2['Enlaces Externos Wayback']:
        comunes = dominio1['Enlaces Externos Wayback'].intersection(dominio2['Enlaces Externos Wayback'])
        print(f"{Fore.YELLOW}Enlaces comunes: {Fore.GREEN}{comunes}{Style.RESET_ALL}")

# Función para mostrar resultados formateados
def mostrar_resultados(datos_dominio, dominio_principal):
    print(f"{Fore.CYAN}Datos para el dominio: {dominio_principal}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Resultados Google:{Style.RESET_ALL}")
    for link in datos_dominio['Resultados Google']:
        print(f"{Fore.GREEN}- {link}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Subdominios:{Style.RESET_ALL}")
    for subdominio in datos_dominio['Subdominios']:
        print(f"{Fore.GREEN}- {subdominio}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Registros DNS:{Style.RESET_ALL}")
    if datos_dominio['Registros DNS']:
        for key, value in datos_dominio['Registros DNS'].items():
            print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron registros DNS.{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Información WHOIS:{Style.RESET_ALL}")
    if datos_dominio['Información WHOIS']:
        for key, value in datos_dominio['Información WHOIS'].items():
            print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontró información WHOIS.{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Certificado SSL/TLS:{Style.RESET_ALL}")
    if datos_dominio['Certificado SSL/TLS']:
        for key, value in datos_dominio['Certificado SSL/TLS'].items():
            print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontró certificado SSL/TLS.{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Enlaces Externos Wayback:{Style.RESET_ALL}")
    for enlace in datos_dominio['Enlaces Externos Wayback']:
        print(f"{Fore.GREEN}- {enlace}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}Enlaces Redes Sociales:{Style.RESET_ALL}")
    for enlace in datos_dominio['Enlaces Redes Sociales']:
        print(f"{Fore.GREEN}- {enlace}{Style.RESET_ALL}")

# Ejemplo de uso
if __name__ == "__main__":
    api_key = input("Introduce tu clave API de SerpApi: ")
    dominio_principal = input("Introduce el dominio principal a analizar: ")
    datos_dominio_principal = recopilar_y_correlacionar_datos(dominio_principal, api_key)

    mostrar_resultados(datos_dominio_principal, dominio_principal)

    if input("\n¿Desea realizar comparaciones entre dominios? (si/no): ").lower() == "si":
        dominios_relacionados = encontrar_dominios_relacionados(dominio_principal, api_key)
        if dominios_relacionados:
            print(f"\n{Fore.CYAN}Dominios relacionados encontrados:{Style.RESET_ALL}")
            for dominio in dominios_relacionados:
                print(f"{Fore.GREEN}- {dominio}{Style.RESET_ALL}")

            for dominio in dominios_relacionados:
                print(f"\n{Fore.CYAN}Recopilando datos para el dominio relacionado: {dominio}{Style.RESET_ALL}")
                datos_dominio_relacionado = recopilar_y_correlacionar_datos(dominio, api_key)
                print(f"\n{Fore.CYAN}Comparación entre {dominio_principal} y {dominio}:{Style.RESET_ALL}")
                comparar_dominios(datos_dominio_principal, datos_dominio_relacionado)
        else:
            print(f"{Fore.RED}No se encontraron dominios relacionados.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}No se realizarán comparaciones entre dominios.{Style.RESET_ALL}")
