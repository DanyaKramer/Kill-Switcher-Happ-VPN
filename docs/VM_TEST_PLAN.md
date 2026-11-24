# Проверка в Ubuntu 22.04 на VMware: SSH и консоль

Используйте отдельную Ubuntu Desktop 22.04 VM со снимком состояния и доступной консолью VMware. Команды firewall меняют исходящий трафик гостевой системы. Команды `on`, `lock` и `off` выполняйте из VMware-консоли: они могут оборвать SSH. SSH подходит для подготовки проекта, модульных тестов и просмотра состояния до включения защиты.

## 1. Подготовка Ubuntu и SSH

В консоли Ubuntu VM выполните:

```bash
sudo apt update
sudo apt install -y openssh-server nftables python3-venv python3-pip tcpdump dnsutils nano
sudo systemctl enable --now ssh
hostname -I
```

Создайте снимок VMware при работающей сети. В Windows PowerShell подставьте имя пользователя и IP VM:

```powershell
Test-NetConnection <IP_VM> -Port 22
ssh <ПОЛЬЗОВАТЕЛЬ_UBUNTU>@<IP_VM>
```

Если SSH не подключается, проверьте в консоли VM `systemctl status ssh`, IP Ubuntu и режим сетевого адаптера VMware (NAT или мост). Оставляйте консоль VMware открытой во время тестов firewall.

## 2. Передача и установка проекта

Из PowerShell в каталоге проекта скопируйте исходники, не копируя Windows `.venv`:

```powershell
ssh <ПОЛЬЗОВАТЕЛЬ_UBUNTU>@<IP_VM> "mkdir -p ~/happ-killswitch"
scp -r src tests docs scripts systemd pyproject.toml README.md config.example.toml <ПОЛЬЗОВАТЕЛЬ_UBUNTU>@<IP_VM>:happ-killswitch/
```

В Ubuntu через SSH создайте окружение Python 3.10 и запустите модульные тесты:

```bash
cd ~/happ-killswitch
python3 --version
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
python3 scripts/install_desktop_launcher.py
```

После установки ярлыка панель можно запускать из меню приложений Ubuntu; она откроется в GNOME Terminal.

Запустите мастер от обычного пользователя, без `sudo`. Он предлагает импорт JSON — другого способа настройки в мастере нет. Скопируйте JSON нужного сервера в Happ, вставьте его в окно `nano`, сохраните и выйдите. Если в JSON несколько узлов VLESS, выберите используемый в Happ. Укажите TUN-интерфейс, который виден в `ip -brief link` при подключённом Happ.

```bash
.venv/bin/happ-killswitch --config config.toml setup
```

Мастер локально читает JSON во временном файле и удаляет его после импорта. В конфиг попадают адрес, порт и транспорт выбранного сервера, но не UUID или ключи.

Для systemd установите отдельную копию программы и сгенерированный конфиг:

```bash
sudo mkdir -p /opt/happ-killswitch /etc/happ-killswitch
sudo cp -a src pyproject.toml /opt/happ-killswitch/
sudo python3 -m venv /opt/happ-killswitch/.venv
sudo /opt/happ-killswitch/.venv/bin/pip install /opt/happ-killswitch
sudo install -m 600 config.toml /etc/happ-killswitch/config.toml
sudo /opt/happ-killswitch/.venv/bin/happ-killswitch --config /etc/happ-killswitch/config.toml check
```

Для первого запуска TUI стартуйте от обычного пользователя. После импорта он запросит административные права. Если конфиг уже существует, следующий запуск также запросит `sudo` до показа панели.

Ubuntu 22.04 поставляет Python 3.10 и nftables 1.0.2. Замена firewall-правил применяется одним пакетом nft. При активном Lock команда `on` использует кэш, не загружая профиль через обычную сеть. Кэш старше 24 часов нужно обновить командой `check` при доступном соединении и до включения Lock.

## 3. Проверка сети и режима «Только VPN»

До включения защиты запишите базовые маршруты и доступность сети:

```bash
ip -brief link
ip route
curl -4 --connect-timeout 5 https://api.ipify.org
curl -6 --connect-timeout 5 https://api64.ipify.org  # проверяйте, если в VM настроен IPv6
dig @1.1.1.1 example.com
```

Затем из консоли VMware включите режим «Только VPN» и убедитесь, что Happ подключён в режиме TUN:

```bash
sudo /opt/happ-killswitch/.venv/bin/happ-killswitch --config /etc/happ-killswitch/config.toml on
```

Проверьте наличие TUN (`ip -brief link`), правила `sudo nft list table inet happ_killswitch`, DNS и внешний IP через VPN. Для проверки прямого обхода попытайтесь явно отправить запрос через физический интерфейс — он должен завершиться ошибкой:

```bash
curl --interface <ФИЗИЧЕСКИЙ_ИНТЕРФЕЙС> --connect-timeout 5 https://1.1.1.1
dig -b <IP_ГОСТЕВОЙ_СИСТЕМЫ> @1.1.1.1 example.com
```

Счётчики `nft` и, при необходимости, `sudo tcpdump -ni <ФИЗИЧЕСКИЙ_ИНТЕРФЕЙС>` должны показывать, что напрямую разрешено соединение только с адресами сервера VLESS. SSH может отключиться после `on`; продолжайте через VMware-консоль.

## 4. Полная блокировка, восстановление и watchdog

Из консоли VMware включите Lock. Проверьте, что не проходят новые IPv4-, IPv6-, DNS-запросы и соединения с сервером VLESS. Затем восстановите доступ командой `off`:

```bash
sudo /opt/happ-killswitch/.venv/bin/happ-killswitch lock
sudo /opt/happ-killswitch/.venv/bin/happ-killswitch --config /etc/happ-killswitch/config.toml off
```

Lock намеренно блокирует и ответы SSH. Команду `off` выполняйте из уже открытой VMware-консоли.

Для проверки watchdog установите и включите службу из консоли:

```bash
sudo cp systemd/happ-killswitch-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now happ-killswitch-watchdog.service
```

Подключите Happ, убедитесь, что TUN существует, затем остановите Happ. После `failure_threshold × interval_seconds` watchdog должен включить Lock. Проверьте, что при появлении TUN обратно сеть не разблокируется автоматически; для возврата в VPN-only вручную запустите `on`. Перезагрузите VM и проверьте стартовую блокировку из консоли. После теста отказов восстановите снимок.

## Критерии прохождения и ограничения

Тест пройден, если доступ через VPN работает, запросы через физический интерфейс блокируются, Lock блокирует весь исходящий трафик кроме loopback, watchdog блокирует сеть после повторного отсутствия TUN, а `off` возвращает обычный доступ, не удаляя чужие таблицы nftables. Если у VM нет IPv6-маршрута, проверка IPv6 не показательна.

Watchdog контролирует наличие TUN, но не обнаруживает зависший туннель или неверные маршруты. Для этого в дальнейшем понадобится отдельная проверка связи через VPN.


