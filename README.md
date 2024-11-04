Mail Spoofing Checker
Este script em Python verifica se um domínio está protegido contra mail spoofing ao analisar as configurações de SPF, DMARC e DKIM.

Funcionalidades:

SPF Check: Verifica a presença de um registro SPF e avalia sua política (-all, ~all, ou ?all), identificando se está configurado de forma segura.

DMARC Check: Verifica se o registro DMARC está presente e corretamente configurado.

DKIM Check: Confirma a presença de um registro DKIM com o seletor padrão (default._domainkey).

Como funciona:

O script consulta os registros DNS para identificar as configurações de autenticação de e-mail. Ele então exibe os resultados e indica se o domínio pode estar vulnerável ao spoofing com base nas políticas encontradas.

Este script é útil para administradores de e-mail e segurança que desejam confirmar se suas configurações DNS oferecem proteção adequada contra falsificação de e-mails.
