#!/usr/bin/env python3
"""
Scanner de CMS (Content Management System)
Versão: 1.0
Baseado em técnicas de fingerprinting de ferramentas como CMSeeK, WPScan e CMS-Detector.
"""

import requests
import argparse
import json
import hashlib
from urllib.parse import urljoin, urlparse
import sys
from bs4 import BeautifulSoup

class CMSScanner:
    def __init__(self, target_url, timeout=10, user_agent=None):
        """
        Inicializa o scanner com o alvo e configurações de rede.
        
        Args:
            target_url (str): URL do site a ser analisado.
            timeout (int): Tempo limite para requisições HTTP.
            user_agent (str): User-Agent personalizado.
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configura um User-Agent padrão ou personalizado
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        else:
            self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        # Estruturas de dados para armazenar resultados
        self.cms_detected = None
        self.version = None
        self.vulnerabilities = []
        self.plugins_detected = {}
        self.themes_detected = {}
        
        print(f"[*] Iniciando scan para: {self.target_url}")
        print(f"[*] Timeout definido para: {self.timeout}s")
        print("-" * 50)

    def fetch_url(self, path=""):
        """
        Função auxiliar para fazer requisições HTTP de forma segura.
        
        Args:
            path (str): Caminho a ser adicionado à URL base.
            
        Returns:
            Response object ou None em caso de erro.
        """
        url = urljoin(self.target_url, path)
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return response
        except requests.exceptions.Timeout:
            print(f"[-] Timeout ao aceder {url}")
        except requests.exceptions.ConnectionError:
            print(f"[-] Erro de conexão ao aceder {url}")
        except Exception as e:
            print(f"[-] Erro inesperado ao aceder {url}: {e}")
        return None

    def detect_cms_by_headers(self):
        """
        Deteta CMS através de cabeçalhos HTTP específicos.
        
        Inspirado na técnica usada pelo CMS-Detector [citation:3].
        """
        print("[*] A analisar cabeçalhos HTTP...")
        response = self.fetch_url()
        if not response:
            return None
        
        headers = response.headers
        cms_signatures = {
            'wordpress': ['X-Pingback', 'X-Powered-By: WP', 'Link: <.*wp-json'],
            'drupal': ['X-Drupal-Cache', 'X-Drupal-Dynamic-Cache', 'X-Generator: Drupal'],
            'joomla': ['X-Content-Encoded-By: Joomla', 'X-Content-Encoded-By: Joomla!'],
            'magento': ['X-Magento-Tags', 'X-Magento-Cache-Id'],
        }
        
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                key, value = sig.split(': ') if ': ' in sig else (sig, None)
                if key in headers:
                    if not value or value in headers[key]:
                        print(f"[+] Possível {cms.capitalize()} detetado via cabeçalho: {sig}")
                        return cms
        return None

    def detect_cms_by_generator_tag(self):
        """
        Deteta CMS através da meta tag 'generator' no HTML.
        
        Técnica clássica e confiável, também usada pelo WPScan [citation:10].
        """
        print("[*] A procurar meta tag 'generator'...")
        response = self.fetch_url()
        if not response:
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        
        if generator_tag and generator_tag.get('content'):
            content = generator_tag['content'].lower()
            cms_signatures = {
                'wordpress': 'wordpress',
                'joomla': 'joomla',
                'drupal': 'drupal',
                'magento': 'magento',
                'wix': 'wix.com',
                'weebly': 'weebly',
            }
            
            for cms, signature in cms_signatures.items():
                if signature in content:
                    print(f"[+] CMS detetado via generator tag: {cms.capitalize()} (conteúdo: {generator_tag['content']})")
                    # Tenta extrair versão, se disponível
                    import re
                    version_match = re.search(r'(\d+\.\d+(\.\d+)?)', generator_tag['content'])
                    if version_match:
                        self.version = version_match.group(1)
                        print(f"[+] Versão detetada: {self.version}")
                    return cms
        return None

    def detect_cms_by_path(self):
        """
        Verifica a existência de caminhos específicos de CMS conhecidos.
        
        Técnica de enumeração agressiva usada por ferramentas como CMSeeK [citation:1].
        """
        print("[*] A verificar caminhos específicos...")
        cms_paths = {
            'wordpress': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-json/', '/xmlrpc.php'],
            'joomla': ['/administrator/', '/components/', '/modules/', '/plugins/', '/media/'],
            'drupal': ['/core/', '/modules/', '/profiles/', '/themes/', '/sites/'],
            'magento': ['/admin/', '/media/', '/static/', '/pub/'],
        }
        
        for cms, paths in cms_paths.items():
            for path in paths:
                response = self.fetch_url(path)
                if response and response.status_code != 404:
                    print(f"[+] Possível {cms.capitalize()} - caminho encontrado: {path} (código: {response.status_code})")
                    return cms
        return None

    def detect_cms_by_cookies(self):
        """
        Deteta CMS através de cookies específicos.
        
        Técnica avançada também referenciada na documentação do CMS-Detector [citation:3].
        """
        print("[*] A analisar cookies...")
        response = self.fetch_url()
        if not response:
            return None
        
        cookies = response.cookies.get_dict()
        cms_cookies = {
            'wordpress': ['wordpress_', 'wp-settings-', 'wp-postpass_'],
            'drupal': ['Drupal.visitor', 'Drupal.toolbar.collapsed'],
            'joomla': ['joomla_user_state', 'joomla_remember_me'],
        }
        
        for cms, signatures in cms_cookies.items():
            for sig in signatures:
                if any(sig in cookie for cookie in cookies.keys()):
                    print(f"[+] Possível {cms.capitalize()} detetado via cookie: {sig}")
                    return cms
        return None

    def fingerprint_version_wordpress(self):
        """
        Tenta identificar a versão exata do WordPress.
        Usa múltiplos métodos para maior precisão.
        
        Inspirado no WPScan, que usa o ficheiro readme.html e a tag generator [citation:10].
        """
        if self.cms_detected != 'wordpress':
            return None
        
        print("[*] A tentar identificar versão do WordPress...")
        
        # Método 1: ficheiro readme.html
        response = self.fetch_url('/readme.html')
        if response and response.status_code == 200:
            import re
            match = re.search(r'Version (\d+\.\d+(\.\d+)?)', response.text)
            if match:
                self.version = match.group(1)
                print(f"[+] Versão WordPress encontrada em readme.html: {self.version}")
                return self.version
        
        # Método 2: feed RSS
        response = self.fetch_url('/feed/')
        if response and response.status_code == 200:
            match = re.search(r'<generator>https?://wordpress\.org/\?v=(\d+\.\d+(\.\d+)?)</generator>', response.text)
            if match:
                self.version = match.group(1)
                print(f"[+] Versão WordPress encontrada no feed RSS: {self.version}")
                return self.version
        
        print("[-] Não foi possível determinar a versão exata do WordPress.")
        return None

    def enumerate_plugins_wordpress(self):
        """
        Enumera plugins WordPress instalados (ataque de força bruta).
        
        Esta técnica é uma das mais poderosas do WPScan e permite identificar vetores de ataque [citation:10].
        """
        if self.cms_detected != 'wordpress':
            return
        
        print("[*] A enumerar plugins WordPress (força bruta)...")
        
        # Lista de plugins comuns (isto seria idealmente carregado de um ficheiro)
        common_plugins = [
            'akismet', 'contact-form-7', 'elementor', 'wordfence', 'yoast-seo', 
            'woocommerce', 'jetpack', 'all-in-one-seo-pack', 'wp-super-cache',
            'wp-rocket', 'nextgen-gallery', 'wpforms', 'google-analytics-for-wordpress'
        ]
        
        for plugin in common_plugins:
            # Verifica se o diretório do plugin existe
            response = self.fetch_url(f'/wp-content/plugins/{plugin}/readme.txt')
            if response and response.status_code == 200:
                self.plugins_detected[plugin] = {'status': 'active'}
                print(f"[+] Plugin encontrado: {plugin}")
                
                # Tenta extrair versão do readme.txt
                import re
                version_match = re.search(r'Stable tag:\s*(\d+\.\d+(\.\d+)?)', response.text)
                if version_match:
                    self.plugins_detected[plugin]['version'] = version_match.group(1)
                    print(f"    ↳ Versão: {version_match.group(1)}")
        
        print(f"[*] Total de plugins encontrados: {len(self.plugins_detected)}")

    def check_vulnerabilities(self):
        """
        Verifica vulnerabilidades conhecidas para o CMS e versão detetados.
        Idealmente, isto consultaria uma API externa como a WPVulnerability [citation:2] ou a VulnTitan [citation:7].
        """
        print("[*] A verificar vulnerabilidades conhecidas...")
        
        # Exemplo simplificado - numa implementação real, isto consultaria uma base de dados
        if self.cms_detected == 'wordpress' and self.version:
            # Simulação de consulta a API de vulnerabilidades
            vuln_db = {
                '6.9': ['CVE-2026-3222 (WP Maps plugin SQL Injection)', 'CVE-2026-23550 (Modular DS - Privilege Escalation)'],
                '6.8': ['CVE-2025-12345 (Core - XSS)', 'CVE-2025-67890 (Plugin X - SQLi)'],
            }
            
            # Verifica versões que correspondem ao padrão
            for ver, vulns in vuln_db.items():
                if self.version.startswith(ver):
                    self.vulnerabilities.extend(vulns)
                    for vuln in vulns:
                        print(f"[!] VULNERABILIDADE ENCONTRADA: {vuln}")
        
        # Verifica plugins vulneráveis
        for plugin, info in self.plugins_detected.items():
            if 'version' in info:
                # Simulação - consulta real a base de dados de vulnerabilidades
                if plugin == 'wp-maps' and info['version'] <= '4.9.1':
                    vuln = f"{plugin} {info['version']} - SQL Injection (CVE-2026-3222)"
                    self.vulnerabilities.append(vuln)
                    print(f"[!] VULNERABILIDADE EM PLUGIN: {vuln}")

    def run_scan(self):
        """
        Executa o scan completo com todas as técnicas.
        
        Esta função coordena todas as fases da análise.
        """
        # Fase 1: Deteção do CMS usando múltiplos métodos
        detection_methods = [
            self.detect_cms_by_headers,
            self.detect_cms_by_generator_tag,
            self.detect_cms_by_cookies,
            self.detect_cms_by_path,
        ]
        
        for method in detection_methods:
            result = method()
            if result:
                self.cms_detected = result
                break
        
        if not self.cms_detected:
            print("[-] Não foi possível detetar o CMS.")
            return
        
        print(f"\n[✓] CMS DETETADO: {self.cms_detected.upper()}")
        
        # Fase 2: Deteção de versão
        if self.cms_detected == 'wordpress':
            self.fingerprint_version_wordpress()
        
        # Fase 3: Enumeração de componentes (apenas para WordPress, por enquanto)
        if self.cms_detected == 'wordpress':
            self.enumerate_plugins_wordpress()
        
        # Fase 4: Verificação de vulnerabilidades
        self.check_vulnerabilities()
        
        # Fase 5: Relatório final
        self.generate_report()

    def generate_report(self):
        """
        Gera um relatório final em formato legível e JSON.
        """
        print("\n" + "="*50)
        print("RELATÓRIO FINAL")
        print("="*50)
        
        report = {
            'target': self.target_url,
            'cms_detected': self.cms_detected,
            'version': self.version,
            'plugins_detected': self.plugins_detected,
            'themes_detected': self.themes_detected,
            'vulnerabilities': self.vulnerabilities,
        }
        
        # Relatório legível
        if self.cms_detected:
            print(f"CMS: {self.cms_detected}")
            print(f"Versão: {self.version or 'Desconhecida'}")
            
            if self.plugins_detected:
                print(f"\nPlugins encontrados ({len(self.plugins_detected)}):")
                for plugin, info in self.plugins_detected.items():
                    version_info = f" (versão: {info.get('version', 'desconhecida')})" if 'version' in info else ""
                    print(f"  - {plugin}{version_info}")
            
            if self.vulnerabilities:
                print(f"\n⚠️ VULNERABILIDADES ENCONTRADAS ({len(self.vulnerabilities)}):")
                for vuln in self.vulnerabilities:
                    print(f"  [!] {vuln}")
            else:
                print("\n[✓] Nenhuma vulnerabilidade conhecida encontrada.")
        else:
            print("Nenhum CMS detetado.")
        
        # Guarda relatório em JSON
        with open('scan_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[✓] Relatório guardado em 'scan_report.json'")

def main():
    parser = argparse.ArgumentParser(description='Scanner de CMS - Ferramenta de Deteção e Análise de Vulnerabilidades')
    parser.add_argument('url', help='URL do site a analisar (ex: https://exemplo.com)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout para requisições (segundos)')
    parser.add_argument('--user-agent', help='User-Agent personalizado')
    parser.add_argument('--no-color', action='store_true', help='Desativa cores no output')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║              CMS Vulnerability Scanner v1.0              ║
    ║         WordPress | Joomla | Drupal | Magento            ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    scanner = CMSScanner(
        target_url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo utilizador.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
