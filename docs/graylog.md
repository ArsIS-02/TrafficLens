# Интеграция с Graylog

Связь работает в две стороны:

- **TrafficLens → Graylog по GELF.** Итоги задач, совпадения с IOC и находки ретропроверки приходят в Graylog обычными сообщениями. Стрим, алерты и уведомления настраиваются в Graylog как для любого другого источника.
- **Graylog ← TrafficLens: lookup table.** База IOC TrafficLens отдаётся по HTTP в формате CSV. Graylog сверяет с ней свои логи (маршрутизатор, Wazuh, auditd) в реальном времени, а не только трафик, прошедший через TrafficLens.

## 1. Отправка по GELF

Нужен GELF-инпут в Graylog (UDP или TCP). Если он уже есть, например на 12201, подойдёт он же.

В `~/.config/trafficlens.env`:

```
TL_GELF_HOST=host.containers.internal
TL_GELF_PORT=12201
TL_BASE_URL=https://trafficlens.apps.example
```

- **`host.containers.internal`** — адрес хоста изнутри rootless-контейнера Podman. Через него TrafficLens доберётся до Graylog, который работает на том же хосте. Если Graylog на другой машине, укажите её адрес.
- **`TL_BASE_URL`** нужен для ссылок на отчёт в сообщениях. Без него ссылок не будет.
- **Протокол, порог и прочее** задаются в `trafficlens.yaml`, секция `gelf:`: протокол `udp`/`tcp`, порог `min_level` (`suspicious` или `critical`), отправка отдельных IOC-совпадений `send_ioc_hits`.

После `systemctl --user restart trafficlens` на странице «Индикаторы и правила» → «Интеграция с Graylog» есть кнопка «Отправить тестовое сообщение». В Graylog оно придёт с `tl_event: test`.

### Какие сообщения приходят

У всех сообщений `tl_source: trafficlens`, поле `source` по умолчанию — `trafficlens`.

| `tl_event` | Когда | Важные поля |
|---|---|---|
| `verdict` | итог задачи не ниже `gelf.min_level`; повторно — только если итог стал строже | `tl_level`, `tl_score`, `tl_file`, `tl_hosts`, `tl_host_names`, `tl_reasons`, `tl_ioc_hits`, `tl_alerts`, `tl_report` |
| `ioc_hit` | каждое совпадение с IOC, один раз на задачу | `tl_ioc_type`, `tl_ioc_value`, `tl_ioc_source`, `tl_ioc_info`, `tl_ioc_conf`, `tl_hosts`, `tl_host_names`, `tl_observed`, `tl_contexts`, `tl_report` |
| `retro_hit` | ретропроверка нашла совпадение в прошлом трафике | `tl_ioc_*`, `tl_observed`, `tl_seen_ts` — когда это было в трафике |
| `test` | кнопка проверки | — |

Общие поля у всех событий: `tl_job`, `tl_file`, `tl_job_source` (`upload`/`capture`/`cli`), `tl_level`, `tl_score`.

`level` по syslog: `2` (critical) — компрометация, IOC с уверенностью ≥ 70 и ретро-совпадения; `4` (warning) — подозрительно и IOC с низкой уверенностью.

Уже отправленное повторно не уходит: после «Пересверить IOC» Graylog получит только новые совпадения. Ошибки сети пишутся в журнал и на страницу индикаторов, анализ из-за них не останавливается.

### Стрим и алерт в Graylog

1. **Streams → Create stream** «TrafficLens». Правило: поле `tl_source` должно совпадать с `trafficlens`. Включите «Remove matches from Default Stream».
2. **Alerts → Event Definitions → Create**. Тип — Filter & Aggregation, стрим «TrafficLens», запрос:
   ```
   tl_event:retro_hit OR (tl_event:verdict AND tl_level:critical)
   ```
   Окно и интервал — 1 минута. Добавьте Notification, которую вы используете для остальных алертов.
3. Для отдельного алерта на каждый IOC используйте запрос `tl_event:ioc_hit AND tl_ioc_conf:>=70`.

## 2. Выгрузка IOC в lookup table

TrafficLens отдаёт базу IOC по адресу `/export/iocs.csv`. Выгрузка включается токеном. Сгенерируйте его:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

и добавьте в `~/.config/trafficlens.env`:

```
TL_EXPORT_TOKEN=<токен>
```

Проверка (Graylog на том же хосте ходит на порт, опубликованный контейнером):

```bash
curl -s "http://127.0.0.1:8095/export/iocs.csv?token=<токен>" | head -3
# value,type,source,info,confidence
# 203.0.113.66,ip,custom,C2 из расследования,100
```

| Параметр | По умолчанию | |
|---|---|---|
| `token` | — | обязателен. Можно передать заголовком `X-TrafficLens-Token` |
| `types` | все, кроме `cidr` | через запятую: `ip,domain,url,md5,sha1,sha256,ja3,ja4,cidr` |
| `min_conf` | `export.min_conf` (50) | минимальная уверенность индикатора |
| `header` | `1` | `0` — без строки заголовка. Нужно для Graylog |

Одна строка — один индикатор. Если индикатор есть в нескольких источниках, они перечисляются через `|`. Когда у индикатора нет описания, в колонке `info` стоит список источников, поэтому значение никогда не бывает пустым.

### Настройка в Graylog 7

Готовые определения событий, правила pipeline для банов Keenetic и входов в Linux и Windows, а также скрипт, который создаёт таблицу, лежат в [Graylog_streams-alerts, глава 20](https://github.com/ArsIS-02/Graylog_streams-alerts/blob/main/docs/20-trafficlens.md). Ниже — то же вручную.

Адаптер «DSV File from HTTP» берёт колонки **по номерам, с нуля**, и строку заголовка не пропускает. Поэтому в URL стоит `header=0`, ключ — колонка `0` (`value`), значение — колонка `3` (`info`).

1. **System → Configurations → URL Whitelist.** Добавьте `http://127.0.0.1:8095/export/iocs.csv?token=<токен>&types=ip,domain&header=0` (тип Exact match) или регулярное выражение `^http://127\.0\.0\.1:8095/export/iocs\.csv\?.*$`. Без этого адаптер не скачает файл.
2. **System → Lookup Tables → Data Adapters → Create.**
   - Тип: «DSV File from HTTP».
   - File URL: тот же адрес, что в whitelist.
   - Refresh interval: `3600`.
   - Separator: `,`, Line separator: `\n`, Quote character: `"`, Ignore characters: `#`.
   - Key column: `0`, Value column: `3`.
   - Включите «Allow case-insensitive lookups».
3. **Caches → Create:** Node-local, in-memory.
4. **Lookup Tables → Create** `trafficlens-iocs` из адаптера и кеша.
5. Правило пайплайна, например для логов маршрутизатора с полем `dst_ip`:
   ```
   rule "TrafficLens IOC: dst_ip"
   when
     has_field("dst_ip") && lookup_has_value("trafficlens-iocs", to_string($message.dst_ip))
   then
     set_field("tl_ioc_hit", true);
     set_field("tl_ioc_info", lookup_value("trafficlens-iocs", to_string($message.dst_ip)));
   end
   ```
   Event definition на `tl_ioc_hit:true` превращает это в алерт.

Подсети (`cidr`) по умолчанию в выгрузку не входят: адаптер DSV сравнивает ключи только точно, поиска по CIDR у него нет.

## 3. Имена локальных хостов

В отчёте, на графе, в карточке хоста и в сообщениях GELF (поле `tl_host_names` рядом с `tl_hosts`) у локальных адресов показываются имена. Если источников несколько, побеждает первый по порядку:

1. **`hosts.yaml`** — файл `<каталог данных>/config/hosts.yaml` (в контейнере `/data/config/hosts.yaml`). Нужен для устройств, которых нет в DNS: роутер, телефоны, гостевые ноутбуки.
   ```yaml
   192.168.1.1: router
   192.168.1.20: nas
   # или списком:
   # - {ip: 192.168.1.30, name: printer}
   ```
   Файл перечитывается при каждом анализе, перезапуск не нужен. Для старых задач нажмите «Пересверить IOC».
2. Имя из DNS-ответов в самом трафике и SNI.
3. Имя из DHCP.
4. **Обратный DNS (PTR)** через резолвер контейнера: запросы идут параллельно с таймаутом, результаты кешируются на час, промахи — на 10 минут.

Настройки в `trafficlens.yaml`:

```yaml
names:
  ptr: true            # false — не делать PTR-запросов
  ptr_timeout: 3.0     # секунд на весь пакет запросов
  max_lookups: 256     # не больше адресов за задачу
  strip_domain: false  # true — host.corp.local → host
  hosts_file: ""       # другой путь к hosts.yaml
```

PTR работает, только если резолвер знает обратную зону. Проверка с хоста: `dig -x <адрес> @<DNS-сервер>`. Пустой ответ при существующей зоне `x.168.192.in-addr.arpa` означает, что для адреса нет PTR-записи. Во FreeIPA её создаёт `ipa dnsrecord-add` или флажок «Create reverse» при добавлении A-записи. Чтобы контейнер ходил к нужному DNS, добавьте в quadlet `DNS=<адрес>`.
