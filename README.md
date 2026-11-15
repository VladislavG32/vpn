# Личный VPN: AmneziaVPN + Happ

Ubuntu **22.04/24.04**, публичный IPv4, KVM и `/dev/net/tun`, Docker Compose **>= 2.33.1**. Для Android и Windows с обновленными приложениями.

| Приложение | Протокол | Внешний порт |
| --- | --- | --- |
| AmneziaVPN | AmneziaWG 3.1 | Случайный UDP, сохраняется в data |
| Happ | VLESS + REALITY + XHTTP stream-one, fingerprint chrome | 443/tcp |

Личная HTTPS-страница содержит ключ Amnezia, подписку Happ, VLESS-ссылку и QR. После установки ссылки выводятся в терминал. Домен покупать не требуется: сертификат выпускается на IP. Портал работает на **2087/tcp**, для выпуска и обновления сертификата нужен **80/tcp**.

## Инструкция по развертыванию на новом сервере

Купите VPS с Ubuntu 24.04 или 22.04, публичным IPv4 и доступным TUN (предпочтительно KVM). Для сборки рекомендуются 2 vCPU, 2 GB RAM и 10 GB свободного диска. Провайдер должен разрешать VPN и исходящий интернет.

Войдите с компьютера по SSH, заменив IP:

```bash
ssh root@SERVER_IP
```

На новом VPS:

```bash
apt-get update && apt-get install -y git
mkdir -p /opt && cd /opt
git clone https://github.com/VladislavG32/vpn.git
cd vpn && bash install.sh
```

Установщик обновляет Ubuntu, ставит Docker и зависимости, собирает закрепленные версии VPN, создает ключи, проверяет конфигурации и запускает сервисы. Сборка занимает несколько минут. Перезагрузка не выполняется автоматически. В конце будут ссылки вида:

```text
denis: https://SERVER_IP:2087/p/СЕКРЕТНЫЙ_ТОКЕН/
vlad: https://SERVER_IP:2087/p/СЕКРЕТНЫЙ_ТОКЕН/
```

Откройте свою страницу, импортируйте ключ в AmneziaVPN и адрес подписки в Happ. Включайте одно VPN-приложение за раз. Повторный вывод страниц: `bash users.sh links`.

Локальные разрешения iptables и уже активного UFW добавляются автоматически без сброса SSH/политик. **Firewall в панели хостинга управляется отдельно:** разрешите 443/tcp, 2087/tcp, 80/tcp и UDP-порт из вывода установщика. Без API провайдера скрипт не может открыть внешний firewall. Порт 80 слушается только во время проверки сертификата; обновление запускается каждые 12 часов.

Если сертификат не выпустился, VPN продолжает работать; причина — в `data/portal/last-issuance.log`. После устранения причины: `bash portal.sh enable`. Без веб-страниц: `PORTAL_ENABLED=0 bash install.sh`; профили останутся в `data/output`, прямые ссылки Happ — `bash users.sh raw`.

## Обновление существующего сервера с AWG 2

Сначала обновите AmneziaVPN и Happ **на всех устройствах**. Это явная миграция; обычные git pull и setup сами ее не включают.

```bash
cd /opt/vpn && git pull --ff-only && bash harden.sh
```

Команда пересобирает образ, проверяет SNI и заменяет только неподходящий; генерирует согласованные параметры AWG 3.1, переключает fingerprint Happ на Chrome, оставляет один XHTTP на 443 и убирает публикацию 8443. Аккаунт router отключается без удаления ключей.

**После перехода откройте прежнюю личную страницу, заново импортируйте ключ Amnezia и обновите подписку Happ.** Старый профиль Amnezia перестанет подходить. UUID, серверные/клиентские ключи, PSK, UDP-порт и токены страниц сохраняются. Прямая VLESS-ссылка изменится из-за fingerprint и, возможно, SNI. Адрес подписки Happ остается прежним и получает новый профиль.

Повторный harden не меняет HeaderProtectionKey. Старые поколения остаются на диске. При ошибке запуска конфигурация откатывается автоматически. Ручной возврат к поколению перед последним успешным переключением:

```bash
bash manage.sh rollback
```

Откат восстанавливает соответствующие порты и профили: используйте клиентские ключи того поколения. Следующее успешное обновление заменяет previous; для долговременного хранения нужен бэкап. Перезапуск не меняет previous.

До миграции схема 1 запускает 443 и 8443 через `docker-compose.legacy.yml`. Используйте скрипты управления: прямой docker compose не выбирает legacy-overlay автоматически.

## Обфускация и ограничения

AWG 3.1: случайный 32-байтный HeaderProtectionKey, одинаковые случайные S1–S4 не менее 12, ограниченный Content Padding, Random Trailers, случайные интервалы rekey/keepalive, junk-пакеты и DisableCookies. H1–H4 равны 1/2/3/4: тип пакета скрывает Header Protection. [Рекомендации AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/). DisableCookies убирает ответы-cookie, меняя поведение защиты от DoS. Фиктивные QUIC-пакеты из примеров синтаксиса не используются.

Уже доступный kernel-модуль выбирается только после проверки принятия и чтения обязательных AWG 3 параметров. Иначе работает Go-реализация. Новый kernel/DKMS не устанавливается; SYS_MODULE не выдается. MTU 1280 и MSS clamp помогают с частью проблем фрагментации; обфускация расходует трафик и CPU.

REALITY выбирает внешний TLS-target из **28 кандидатов** в `configs/sni-domains.txt`: сайты Sony, NVIDIA, Samsung, Python, Debian и другие. Новый setup случайно перебирает домены, проверяет сертификат, TLS 1.3, h2, публичные адреса и признаки Cloudflare. Исключены .ru/.cn и gateway.icloud.com, о котором предупреждала используемая версия Xray. Это не закрепленная маскировка под аниме-сайт. Обычный повторный setup сохраняет SNI; harden и optimize заменяют только не прошедший проверку. Снимок сетей Cloudflare требует обслуживания; проверки не доказывают постоянное отсутствие CDN. [REALITY](https://xtls.github.io/en/config/transports/reality.html).

При поддержке ядром включаются BBR, default_qdisc=fq и TCP MTU probing без замены ядра и физических qdisc. Исходные sysctl — `data/tuning/original.conf`, примененные — `/etc/sysctl.d/90-private-vpn.conf`. Возврат на том же сервере: `sysctl -p data/tuning/original.conf` и `bash manage.sh restart`; для сохранения после reboot замените также sysctl-файл исходными значениями. BBR не ускоряет сам UDP AWG.

**Необнаружимость, рост скорости и обход любого DPI не гарантируются.** Блокировка IP, всего UDP или разрешение только отдельных сайтов могут затронуть оба способа. Смена SNI не разблокирует IP. Один VPS не является HA-кластером: есть восстановление процессов и перенос, но при отказе хостинга нужен другой сервер.

## Пользователи

Активны denis, vlad, liza, parents, svyat, sveta, ruslan. Восьмой аккаунт router сохраняется отключенным ради совместимости данных. Инструкций про роутер на страницах нет.

```bash
bash users.sh list
bash users.sh links vlad    # личная страница
bash users.sh show vlad     # VLESS и QR в терминале
bash users.sh raw vlad      # прямая ссылка Happ
bash users.sh rotate vlad   # новые ключи И токен страницы
bash users.sh disable vlad
bash users.sh enable vlad
```

rotate отзывает старые подключения и страницу пользователя; остальные сохраняются. disable удаляет его страницу и доступ. Профили, страницы и QR содержат секреты. Нестандартные awg:// ссылки не выдаются: для Amnezia используется настоящий формат vpn://.

## DNS и сеть

DNScrypt-proxy шифрует запросы к закрепленным AdGuard upstream без обычного plaintext DNS fallback. Xray блокирует рекламные домены через blackhole; AWG перехватывает обычный DNS/53. Ограничены частные сети, metadata, межклиентский трафик и DoT/853. Клиентский IPv6 захватывается и не выпускается сервером. Контейнеры используют внутреннюю backend-сеть и отдельную egress-сеть для выхода.

Приложения со своим DoH могут обходить DNS-фильтр. Устройства без туннеля, split tunneling и клиентские маршруты требуют отдельной проверки. **DNS не удаляет надежно рекламу YouTube:** блокировка общих с видео доменов ломает просмотр. [Пояснение AdGuard](https://adguard.com/en/support/adguard-mini-android/about/about_the_settings/video_browser/youtube_hard_to_block.html).

## Миграция при смене сервера/IP

Все переносимые данные в `data`, права root 0700/0600; каталог исключен из Git. Не запускайте скопированные экземпляры с одинаковыми профилями одновременно.

На старом VPS:

```bash
cd /opt/vpn
bash manage.sh backup   # зашифрованный GPG-архив, запросит пароль
systemctl stop private-vpn-health.timer private-vpn-portal-renew.timer
docker compose --profile portal down
tar -C /opt/vpn -czf - data | ssh root@NEW_IP 'umask 077; mkdir -p /opt/vpn-transfer; tar -xzf - -C /opt/vpn-transfer'
```

Для legacy-схемы при остановке добавьте `-f docker-compose.yml -f docker-compose.legacy.yml` перед `--profile`. Старый VPS сохраните до проверки нового.

На новом VPS:

```bash
apt-get update && apt-get install -y git
mkdir -p /opt && cd /opt
git clone https://github.com/VladislavG32/vpn.git
mv /opt/vpn-transfer/data /opt/vpn/data
cd /opt/vpn
ENDPOINT=NEW_IP bash install.sh
```

Передача через tar/SSH сохраняет относительные симлинки current/output/previous; scp -r для каталога data не используйте. Сертификат перевыпустится, новый адрес попадет в профили. Ключи, параметры AWG, SNI и токены сохраняются. Откройте страницы по новому IP, переимпортируйте Amnezia и замените адрес подписки Happ. При постоянном DNS-имени задайте его как ENDPOINT и обновите A-запись с учетом TTL. Смена адреса без полной установки: `bash manage.sh migrate NEW_IP`.

Бэкап включает активное поколение и состояние портала, но не историю. Восстановление: расшифруйте архив в **пустой** data, запустите установщик с новым ENDPOINT. Полная копия data сохраняет также историю и архивы. Не добавляйте data в Git даже для приватного репозитория.

## Проверки и обслуживание

```bash
cd /opt/vpn
bash manage.sh status
bash manage.sh test-vless vlad
bash manage.sh diagnose
bash manage.sh logs xray
bash manage.sh logs awg
bash manage.sh restart
bash optimize.sh
```

healthy проверяет локальную готовность. test-vless выполняет прямой HTTPS-запрос и запрос через временный Xray по Docker-сети: XHTTP для схемы 2, XHTTP и TCP для схемы 1. SOCKS слушает localhost со случайным паролем; временные клиенты удаляются. Ключи и сервисы не меняются. SERVER_TEST: OK подтверждает серверную цепочку, **но не обход DPI из клиентской сети**. AWG проверяйте по handshake и счетчикам diagnose; действующий ключ клиента не используется для серверного теста.

Если серверные проверки успешны, сравните на устройстве Wi-Fi и мобильную сеть, оба приложения по очереди, время и актуальность импортированного профиля. Для скорости сравните download/upload/ping с загрузкой CPU в diagnose.

Таймер private-vpn-health.timer раз в минуту перезапускает unhealthy/exited сервисы, Docker запускается после reboot. Сетевую блокировку и отказ VPS таймер не исправляет. Журналы ограничены; access/query-логи выключены, предупреждения могут содержать адреса. Портал монтирует только webroot и TLS, без state.json; корень возвращает 404, страницы запрещают кеширование/referrer.

```bash
python3 -m unittest discover -s tests -v
bash tests/smoke_awg.sh   # Linux с Docker/TUN; только синтетические ключи
```

GitHub Actions проверяет тесты, сборку закрепленных исходников, Xray и реальный AWG 3 handshake с передачей пакетов в изолированных контейнерах. Это не заменяет проверку импорта Android/Windows и сетей провайдера. Xray 26.11.9, dnscrypt-proxy 2.1.20, AWG Go/tools закреплены SHA в configs/Dockerfile. Go/Alpine и apt/apk не закреплены digest/snapshot: сборка не побитово воспроизводима. Автообновлений протоколов нет; обновляйте после бэкапа и проверки.
