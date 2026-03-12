# 🔍 CMS Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)](CONTRIBUTING.md)

Uma ferramenta avançada de scanning para deteção de Content Management Systems (CMS) e análise de vulnerabilidades. Inspirada nas melhores ferramentas do mercado como WPScan, CMSeeK e CMS-Detector.

##  Sobre o Projeto

Este scanner foi desenvolvido para automatizar o processo de reconhecimento e auditoria de segurança em sites baseados em CMS. Utiliza múltiplas técnicas de fingerprinting para identificar com precisão o CMS, versão, plugins instalados e vulnerabilidades conhecidas.

### Características Principais

- **Multi-CMS Support**: Deteção de WordPress, Joomla, Drupal e Magento
- **Fingerprinting Avançado**: 4 métodos diferentes de identificação
- **WordPress Deep Scan**: Versão exata, plugins e temas
- **Verificação de Vulnerabilidades**: Base de dados integrada de CVEs
- **Relatórios Detalhados**: Output em formato legível e JSON
- **Modular e Extensível**: Fácil adicionar novos CMSs e vulnerabilidades

##  Instalação

### Pré-requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Passos de Instalação

1. **Clone o repositório**
```bash
git clone https://github.com/seu-usuario/cms-vulnerability-scanner.git
cd cms-vulnerability-scanner
