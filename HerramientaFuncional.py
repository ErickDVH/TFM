import requests
import whois
import socket
import ssl
from bs4 import BeautifulSoup
import time
import random
from urllib.parse import urlparse
from colorama import Fore, Style, Back, init
import csv
import os

init(autoreset=True)

# Función para buscar en Google usando Google Custom Search API
def buscar_en_google_custom_search(consulta, api_key, cx):
    params = {
        'key': api_key,
        'cx': cx,
        'q': consulta
    }
    try:
        response = requests.get("https://www.googleapis.com/customsearch/v1", params=params)
        response.raise_for_status()
        json_response = response.json()
        if 'items' in json_response:
            results = json_response['items']
            links = [item['link'] for item in results if 'link' in item]
            return links
        else:
            print("No se encontraron resultados en la respuesta.")
            return []
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return []

# Función para buscar subdominios usando crt.sh
def buscar_subdominios(dominio):
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{dominio}&output=json")
        response.raise_for_status()
        subdomains = set(entry['name_value'] for entry in response.json())
        return subdomains
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return set()

# Función para analizar registros DNS
def analizar_dns(dominio):
    try:
        respuesta_dns = socket.gethostbyname_ex(dominio)
        return {'Tipo de registro': respuesta_dns[0], 'Datos': respuesta_dns[2]} if respuesta_dns[2] else None
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
        print("Error al buscar certificados SSL/TLS:", e)
        return None

# Función para obtener enlaces de una página web usando BeautifulSoup
def obtener_enlaces_pagina(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        enlaces = set(a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http'))
        return enlaces
    except requests.RequestException as e:
        print("Error de conexión:", e)
        return set()

# Función para obtener enlaces de Wayback Machine
def obtener_enlaces_wayback(dominio):
    enlaces_wayback = set()
    try:
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={dominio}&output=json&fl=original")
        response.raise_for_status()
        resultados = response.json()
        for resultado in resultados[1:]:
            enlaces_wayback.add(resultado[0])
    except requests.RequestException as e:
        print("Error de conexión:", e)
    return enlaces_wayback

# Función para obtener enlaces externos de Wayback Machine
def obtener_enlaces_externos_wayback(dominio):
    urls_wayback = obtener_enlaces_wayback(dominio)
    enlaces_externos = set()
    for url in urls_wayback:
        enlaces_pagina = obtener_enlaces_pagina(url)
        for enlace in enlaces_pagina:
            dominio_enlace = urlparse(enlace).netloc
            if dominio != dominio_enlace and dominio_enlace:
                enlaces_externos.add(dominio_enlace)
        time.sleep(random.uniform(1, 3))  # Añade un pequeño retraso entre solicitudes
    return enlaces_externos

# Función para obtener enlaces de redes sociales
def obtener_enlaces_redes_sociales(dominio, api_key, cx):
    social_links = set()
    redes_sociales = ["twitter.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com"]
    for red in redes_sociales:
        print(f"Buscando en {red} para {dominio}...")
        consulta = f"site:{red} {dominio}"
        links = buscar_en_google_custom_search(consulta, api_key, cx)
        if links:
            social_links.update(links)
        time.sleep(random.uniform(1, 3))  # Añade un pequeño retraso entre solicitudes para evitar problemas de tasa de peticiones
    return social_links

# Función para recopilar y correlacionar datos del dominio
def recopilar_y_correlacionar_datos(dominio, api_key, cx, verbose=False):
    print(f"\n{Back.YELLOW}{Fore.BLACK}Recopilando resultados de búsqueda en Google...{Style.RESET_ALL}")
    resultados_google = buscar_en_google_custom_search(dominio, api_key, cx)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Recopilando subdominios...{Style.RESET_ALL}")
    subdominios = buscar_subdominios(dominio)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Analizando registros DNS...{Style.RESET_ALL}")
    respuesta_dns = analizar_dns(dominio)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Obteniendo información WHOIS...{Style.RESET_ALL}")
    info_whois = analizar_whois(dominio)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Obteniendo certificados SSL/TLS...{Style.RESET_ALL}")
    certificado = certificados_ssl(dominio)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Buscando enlaces externos en Wayback Machine...{Style.RESET_ALL}")
    enlaces_externos_wayback = obtener_enlaces_externos_wayback(dominio)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Buscando enlaces en redes sociales...{Style.RESET_ALL}")
    enlaces_redes_sociales = obtener_enlaces_redes_sociales(dominio, api_key, cx)

    if verbose:
        print(f"\n{Back.GREEN}{Fore.BLACK}Resultados encontrados en Google para {dominio}:{Style.RESET_ALL}")
        for result in resultados_google:
            print(f"{Fore.LIGHTBLUE_EX}{result}{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}Subdominios encontrados para {dominio}:{Style.RESET_ALL}")
        for sub in subdominios:
            print(f"{Fore.LIGHTBLUE_EX}{sub}{Style.RESET_ALL}")

        if respuesta_dns:
            print(f"\n{Back.GREEN}{Fore.BLACK}Registros DNS encontrados para {dominio}:{Style.RESET_ALL}")
            for key, value in respuesta_dns.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No se encontraron registros DNS para {dominio}.{Style.RESET_ALL}")

        if info_whois:
            print(f"\n{Back.GREEN}{Fore.BLACK}Información WHOIS encontrada para {dominio}:{Style.RESET_ALL}")
            for key, value in info_whois.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No se encontró información WHOIS para {dominio}.{Style.RESET_ALL}")

        if certificado:
            print(f"\n{Back.GREEN}{Fore.BLACK}Certificado SSL/TLS encontrado para {dominio}:{Style.RESET_ALL}")
            for key, value in certificado.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No se encontraron certificados SSL/TLS para {dominio}.{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}Enlaces externos encontrados en Wayback Machine para {dominio}:{Style.RESET_ALL}")
        for enlace in enlaces_externos_wayback:
            print(f"{Fore.LIGHTBLUE_EX}{enlace}{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}Enlaces de redes sociales encontrados para {dominio}:{Style.RESET_ALL}")
        for enlace in enlaces_redes_sociales:
            print(f"{Fore.LIGHTBLUE_EX}{enlace}{Style.RESET_ALL}")
    else:
        # Modo minimalista
        print(f"\n{Back.GREEN}{Fore.BLACK}Resumen de datos recopilados para {dominio}:{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Resultados Google: {len(resultados_google)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Subdominios: {len(subdominios)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Registros DNS: {len(respuesta_dns) if respuesta_dns else 0}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Información WHOIS: {len(info_whois) if info_whois else 0}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Certificado SSL/TLS: {'Sí' if certificado else 'No'}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Enlaces Externos Wayback: {len(enlaces_externos_wayback)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Enlaces Redes Sociales: {len(enlaces_redes_sociales)}{Style.RESET_ALL}")

    return {
        'resultados_google': resultados_google,
        'subdominios': subdominios,
        'respuesta_dns': respuesta_dns,
        'info_whois': info_whois,
        'certificado': certificado,
        'enlaces_externos_wayback': enlaces_externos_wayback,
        'enlaces_redes_sociales': enlaces_redes_sociales
    }

# Función para encontrar dominios relacionados automáticamente con WayBack Machine
def encontrar_dominios_relacionados_WayBackMachine(dominio_principal):
    resultados = obtener_enlaces_externos_wayback(dominio_principal)
    dominios_relacionados = set()

    # Lista de dominios a excluir (redes sociales y otros dominios no relevantes)
    dominios_excluidos = {
        'www.youtube.com', 'www.facebook.com', 'www.instagram.com', 'www.twitter.com', 'www.linkedin.com', 'www.pinterest.com', 'www.tiktok.com',
        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com', 'es-es.facebook.com'
    }

    for resultado in resultados:
        # Filtra dominios excluidos y dominios principales
        if resultado and resultado != dominio_principal and resultado not in dominios_excluidos:
            dominios_relacionados.add(resultado)
    
    return list(dominios_relacionados)

# Función para encontrar dominios relacionados automáticamente con Google
def encontrar_dominios_relacionados_Google(dominio_principal, api_key, cx):
    consulta = f"site:{dominio_principal}"
    resultados = buscar_en_google_custom_search(consulta, api_key, cx)
    dominios_relacionados = set()
    
    # Lista de dominios a excluir (redes sociales y otros dominios no relevantes)
    dominios_excluidos = {
        'www.youtube.com', 'www.facebook.com', 'www.instagram.com', 'www.twitter.com', 'www.linkedin.com', 'www.pinterest.com', 'www.tiktok.com',
        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com', 'es-es.facebook.com'
    }

    for resultado in resultados:
        dominio_encontrado = urlparse(resultado).netloc
        # Filtra dominios excluidos y dominios principales
        if dominio_encontrado and dominio_encontrado != dominio_principal and dominio_encontrado not in dominios_excluidos:
            dominios_relacionados.add(dominio_encontrado)
    
    return list(dominios_relacionados)

# Función para leer dominios desde un archivo CSV
def leer_dominios_csv(nombre_archivo):
    try:
        with open(nombre_archivo, mode='r', newline='', encoding='utf-8') as archivo:
            lector_csv = csv.reader(archivo)
            dominios = [fila[0] for fila in lector_csv if fila]
            return dominios
    except Exception as e:
        print("Error al leer el archivo CSV:", e)
        return []
    
# Función para comparar dominios
def comparar_dominios(dominio1, dominio2):

    # Comparación de resultados de búsqueda en Google
    print(f"\n{Fore.BLUE}Comparación de resultados de búsqueda en Google:{Style.RESET_ALL}")
    if dominio1.get('resultados_google') and dominio2.get('resultados_google'):
        comunes = set(dominio1['resultados_google']).intersection(set(dominio2['resultados_google']))
        if comunes:
            print(f"{Fore.YELLOW}Resultados comunes en Google: {Fore.GREEN}{comunes}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No se encontraron resultados comunes en Google entre los dominios.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron resultados de búsqueda en Google para uno o ambos dominios.{Style.RESET_ALL}")

    # Comparación de subdominios
    print(f"\n{Fore.BLUE}Comparación de subdominios:{Style.RESET_ALL}")
    if dominio1.get('subdominios') and dominio2.get('subdominios'):
        comunes = set(dominio1['subdominios']).intersection(set(dominio2['subdominios']))
        if comunes:
            print(f"{Fore.YELLOW}Subdominios comunes: {Fore.GREEN}{comunes}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No se encontraron subdominios comunes entre los dominios.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron subdominios para uno o ambos dominios.{Style.RESET_ALL}")
        
    # Comparación de la información WHOIS
    print(f"{Fore.BLUE}Comparación de la información WHOIS:{Style.RESET_ALL}")

    if dominio1.get('info_whois') and dominio2.get('info_whois'):
        if all(value is None for value in dominio1['info_whois'].values()) and all(value is None for value in dominio2['info_whois'].values()):
            print(f"{Fore.RED}No se encontró información WHOIS válida para ninguno de los dominios.{Style.RESET_ALL}")
        else:
            for key in dominio1['info_whois']:
                if key in dominio2['info_whois']:
                    print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Dominio 1: {dominio1['info_whois'].get(key, 'No disponible')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Dominio 2: {dominio2['info_whois'].get(key, 'No disponible')}{Style.RESET_ALL}")
    else:
        if not dominio1.get('info_whois'):
            print(f"{Fore.RED}No se encontró información WHOIS para el Dominio 1.{Style.RESET_ALL}")
        if not dominio2.get('info_whois'):
            print(f"{Fore.RED}No se encontró información WHOIS para el Dominio 2.{Style.RESET_ALL}")

    # Comparación de registros DNS
    print(f"\n{Fore.BLUE}Comparación de registros DNS:{Style.RESET_ALL}")
    if dominio1.get('respuesta_dns') and dominio2.get('respuesta_dns'):
        for key in dominio1['respuesta_dns']:
            if key in dominio2['respuesta_dns']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 1: {dominio1['respuesta_dns'].get(key, 'No disponible')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 2: {dominio2['respuesta_dns'].get(key, 'No disponible')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron registros DNS para uno o ambos dominios.{Style.RESET_ALL}")

    # Comparación de certificados SSL/TLS
    print(f"\n{Fore.BLUE}Comparación de certificados SSL/TLS:{Style.RESET_ALL}")
    if dominio1.get('certificado') and dominio2.get('certificado'):
        for key in dominio1['certificado']:
            if key in dominio2['certificado']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 1: {dominio1['certificado'].get(key, 'No disponible')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Dominio 2: {dominio2['certificado'].get(key, 'No disponible')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron certificados SSL/TLS para uno o ambos dominios.{Style.RESET_ALL}")

    # Comparación de enlaces externos en Wayback Machine
    print(f"\n{Fore.BLUE}Comparación de enlaces externos en Wayback Machine:{Style.RESET_ALL}")
    if dominio1.get('enlaces_externos_wayback') and dominio2.get('enlaces_externos_wayback'):
        comunes = dominio1['enlaces_externos_wayback'].intersection(dominio2['enlaces_externos_wayback'])
        if comunes:
            print(f"{Fore.YELLOW}Enlaces comunes: {Fore.GREEN}{comunes}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No se encontraron enlaces comunes entre los dominios.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron enlaces en Wayback Machine para uno o ambos dominios.{Style.RESET_ALL}")

    # Comparación de enlaces en redes sociales
    print(f"\n{Fore.BLUE}Comparación de enlaces en redes sociales:{Style.RESET_ALL}")
    if dominio1.get('enlaces_redes_sociales') and dominio2.get('enlaces_redes_sociales'):
        comunes = dominio1['enlaces_redes_sociales'].intersection(dominio2['enlaces_redes_sociales'])
        if comunes:
            print(f"{Fore.YELLOW}Enlaces comunes en redes sociales: {Fore.GREEN}{comunes}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No se encontraron enlaces comunes en redes sociales entre los dominios.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron enlaces en redes sociales para uno o ambos dominios.{Style.RESET_ALL}")

# Función para comparar dominios de forma simple
def comparar_dominios_simple(dominio1, dominio2):
    # Inicializa los contadores
    total_criterios = 0
    coincidencias = 0

    # Obtén los nombres de dominio, maneja si no existen
    nombre_dominio1 = dominio1.get('dominio', 'Dominio 1')
    nombre_dominio2 = dominio2.get('dominio', 'Dominio 2')

    # Comparación de información WHOIS
    print(f"\n{Fore.BLUE}Comparación de la información WHOIS:{Style.RESET_ALL}")
    if dominio1.get('info_whois') and dominio2.get('info_whois'):
        for key, value1 in dominio1['info_whois'].items():
            value2 = dominio2['info_whois'].get(key)
            total_criterios += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}Coincidencia en WHOIS: {key} - {value1}{Style.RESET_ALL}")
                coincidencias += 1
            else:
                print(f"{Fore.YELLOW}No hay coincidencia en WHOIS para {key}. {nombre_dominio1}: {value1}, {nombre_dominio2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontró información WHOIS para uno o ambos dominios.{Style.RESET_ALL}")
        total_criterios += 1  # Incrementar para reflejar que se evaluó este criterio

    # Comparación de registros DNS
    print(f"\n{Fore.BLUE}Comparación de registros DNS:{Style.RESET_ALL}")
    if dominio1.get('respuesta_dns') and dominio2.get('respuesta_dns'):
        for key, value1 in dominio1['respuesta_dns'].items():
            value2 = dominio2['respuesta_dns'].get(key)
            total_criterios += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}Coincidencia en DNS: {key} - {value1}{Style.RESET_ALL}")
                coincidencias += 1
            else:
                print(f"{Fore.YELLOW}No hay coincidencia en DNS para {key}. {nombre_dominio1}: {value1}, {nombre_dominio2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron registros DNS para uno o ambos dominios.{Style.RESET_ALL}")
        total_criterios += 1  # Incrementar para reflejar que se evaluó este criterio

    # Comparación de certificados SSL/TLS
    print(f"\n{Fore.BLUE}Comparación de certificados SSL/TLS:{Style.RESET_ALL}")
    if dominio1.get('certificado') and dominio2.get('certificado'):
        for key, value1 in dominio1['certificado'].items():
            value2 = dominio2['certificado'].get(key)
            total_criterios += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}Coincidencia en SSL/TLS: {key} - {value1}{Style.RESET_ALL}")
                coincidencias += 1
            else:
                print(f"{Fore.YELLOW}No hay coincidencia en SSL/TLS para {key}. {nombre_dominio1}: {value1}, {nombre_dominio2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron certificados SSL/TLS para uno o ambos dominios.{Style.RESET_ALL}")
        total_criterios += 1  # Incrementar para reflejar que se evaluó este criterio

    # Calcula el porcentaje de coincidencia
    if total_criterios > 0:
        porcentaje_relacion = (coincidencias / total_criterios) * 100
        print(f"\n{Fore.YELLOW}Porcentaje de relación entre {nombre_dominio1} y {nombre_dominio2}: {Fore.GREEN}{porcentaje_relacion:.2f}%{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No se encontraron criterios suficientes para comparar.{Style.RESET_ALL}")

    # Asegura siempre tener un resultado incluso si no hay coincidencias
    if coincidencias == 0 and total_criterios > 0:
        print(f"{Fore.RED}No se encontraron coincidencias entre {nombre_dominio1} y {nombre_dominio2}.{Style.RESET_ALL}")


# Función para guardar resultados en un archivo CSV
def guardar_en_csv(datos, nombre_archivo):
    try:
        with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as archivo:
            escritor_csv = csv.writer(archivo)
            escritor_csv.writerow(['Dominio', 'Resultados Google', 'Subdominios', 'Registros DNS', 'Información WHOIS', 'Certificado SSL/TLS', 'Enlaces Externos Wayback Machine', 'Enlaces Redes Sociales'])
            for resultado in datos:
                escritor_csv.writerow([
                    resultado.get('dominio', ''),
                    len(resultado.get('resultados_google', [])),
                    len(resultado.get('subdominios', [])),
                    resultado.get('respuesta_dns') is not None,
                    resultado.get('info_whois') is not None,
                    resultado.get('certificado') is not None,
                    len(resultado.get('enlaces_externos_wayback', [])),
                    len(resultado.get('enlaces_redes_sociales', []))
                ])
    except Exception as e:
        print("Error al guardar en el archivo CSV:", e)

# Ejecución de la herramienta
if __name__ == "__main__":
    # Solicita la clave API de Google Custom Search
    while True:
        api_key = input("Introduce tu clave API de Google Custom Search: ").strip()
        if api_key:
            break
        print(f"{Back.RED}{Fore.BLACK}Clave API no válida. Por favor, introduce un valor válido.{Style.RESET_ALL}")
    
    # Solicita el ID de búsqueda personalizada (CX)
    while True:
        cx = input("Introduce el ID de búsqueda personalizada (CX): ").strip()
        if cx:
            break
        print(f"{Back.RED}{Fore.BLACK}ID de búsqueda personalizada (CX) no válido. Por favor, introduce un valor válido.{Style.RESET_ALL}")
    
    # Solicita el modo de operación
    while True:
        modo = input("¿Deseas analizar un dominio o varios dominios desde un archivo CSV? (uno/varios): ").strip().lower()
        if modo in ["uno", "varios"]:
            break
        print(f"{Back.RED}{Fore.BLACK}Modo no reconocido. Por favor, elige 'uno' o 'varios'.{Style.RESET_ALL}")

    if modo == "uno":
        # Solicita el dominio principal a analizar
        while True:
            dominio_principal = input("Introduce el dominio principal a analizar: ").strip()
            if dominio_principal:
                break
            print(f"{Back.RED}{Fore.BLACK}Dominio principal no válido.{Style.RESET_ALL}")

        # Solicita si desea una salida detallada
        verbose = input("¿Desea una salida detallada? (si/no): ").strip().lower() == "si"

        try:
            # Recopila y correlaciona datos del dominio principal
            datos_dominio_principal = recopilar_y_correlacionar_datos(dominio_principal, api_key, cx, verbose=verbose)

            # Opciones de comparaciones entre dominios
            while True:
                opcion_comparacion = input("\n¿Desea realizar comparaciones entre dominios con detalles (Google)? (si/no): ").strip().lower()
                if opcion_comparacion in ["si", "no"]:
                    break
                print(f"{Back.RED}{Fore.BLACK}Opción no válida. Por favor, elige 'si' o 'no'.{Style.RESET_ALL}")

            if opcion_comparacion == "si":
                # Encuentra automáticamente los dominios relacionados
                dominios_relacionados = encontrar_dominios_relacionados_Google(dominio_principal, api_key, cx)
                if dominios_relacionados:
                    print(f"\n{Back.GREEN}{Fore.BLACK}Dominios relacionados encontrados:{Style.RESET_ALL}")
                    for dominio in dominios_relacionados:
                        print(f"{Fore.LIGHTBLUE_EX}{dominio}{Style.RESET_ALL}")

                    for dominio in dominios_relacionados:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Recopilando datos para el dominio relacionado: {dominio}{Style.RESET_ALL}")
                        datos_dominio_relacionado = recopilar_y_correlacionar_datos(dominio, api_key, cx, verbose=verbose)
                        print(f"\n{Back.CYAN}{Fore.BLACK}Comparación entre {dominio_principal} y {dominio}:{Style.RESET_ALL}")
                        comparar_dominios(datos_dominio_principal, datos_dominio_relacionado)
                else:
                    print(f"{Back.RED}{Fore.BLACK}No se encontraron dominios relacionados.{Style.RESET_ALL}")

            else:
                # Pregunta si desea realizar comparaciones sin detalles
                while True:
                    opcion_comparacion_simple = input("\n¿Desea realizar comparaciones entre dominios sin detalles (WayBack Machine)? (si/no): ").strip().lower()
                    if opcion_comparacion_simple in ["si", "no"]:
                        break
                    print(f"{Back.RED}{Fore.BLACK}Opción no válida. Por favor, elige 'si' o 'no'.{Style.RESET_ALL}")

                if opcion_comparacion_simple == "si":
                    # Encuentra automáticamente los dominios relacionados sin detalles
                    dominios_relacionados = encontrar_dominios_relacionados_WayBackMachine(dominio_principal)
                    if dominios_relacionados:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Dominios relacionados encontrados:{Style.RESET_ALL}")
                        for dominio in dominios_relacionados:
                            print(f"{Fore.LIGHTBLUE_EX}{dominio}{Style.RESET_ALL}")

                        for dominio in dominios_relacionados:
                            print(f"\n{Back.GREEN}{Fore.BLACK}Recopilando datos para el dominio relacionado: {dominio}{Style.RESET_ALL}")
                            datos_dominio_relacionado = recopilar_y_correlacionar_datos(dominio, api_key, cx, verbose=verbose)
                            print(f"\n{Back.CYAN}{Fore.BLACK}Comparación entre {dominio_principal} y {dominio}:{Style.RESET_ALL}")
                            comparar_dominios_simple(datos_dominio_principal, datos_dominio_relacionado)
                    else:
                        print(f"{Back.RED}{Fore.BLACK}No se encontraron dominios relacionados.{Style.RESET_ALL}")

                else:
                    print(f"\n{Back.YELLOW}{Fore.BLACK}No se realizarán comparaciones entre dominios.{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Back.RED}{Fore.BLACK}Ocurrió un error: {e}{Style.RESET_ALL}")

    elif modo == "varios":
        # Solicita el nombre del archivo CSV
        while True:
            archivo_csv = input("Introduce el nombre del archivo CSV con los dominios: ").strip()
            if os.path.isfile(archivo_csv):
                break
            print(f"{Back.RED}{Fore.BLACK}El archivo CSV no existe o no es accesible. Por favor, introduce un archivo válido.{Style.RESET_ALL}")

        dominios = leer_dominios_csv(archivo_csv)

        if dominios:
            resultados = []
            for dominio in dominios:
                if dominio:
                    try:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Recopilando datos para el dominio: {dominio}{Style.RESET_ALL}")
                        datos = recopilar_y_correlacionar_datos(dominio, api_key, cx, verbose=True)
                        resultados.append({'dominio': dominio, **datos})
                    except Exception as e:
                        print(f"{Back.RED}{Fore.BLACK}Error al procesar el dominio {dominio}: {e}{Style.RESET_ALL}")

            # Solicita el nombre del archivo CSV de salida
            while True:
                archivo_csv_salida = input("Introduce el nombre del archivo CSV de salida para guardar los resultados: ").strip()
                if archivo_csv_salida:
                    try:
                        guardar_en_csv(resultados, archivo_csv_salida)
                        print(f"{Back.GREEN}{Fore.BLACK}Resultados guardados en {archivo_csv_salida}.{Style.RESET_ALL}")
                        break
                    except Exception as e:
                        print(f"{Back.RED}{Fore.BLACK}Error al guardar los resultados en el archivo CSV: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Back.RED}{Fore.BLACK}Nombre de archivo CSV de salida no válido.{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No se encontraron dominios en el archivo CSV.{Style.RESET_ALL}")
