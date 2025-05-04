# CycleTLSR

Мощный HTTP-клиент для парсинга веб-сайтов с обходом антибот-систем через эмуляцию TLS-отпечатков реальных браузеров.

## Особенности

- 🛡️ **Обход антибот-систем** - Эффективный обход различных систем защиты от ботов
- 🔒 **TLS Fingerprinting** - Точная эмуляция TLS-отпечатков Chrome, Firefox, Safari для скрытного парсинга
- 🔄 **Поддержка прокси** - Ротация HTTP(S)/SOCKS4/SOCKS5 прокси для массового парсинга
- 📊 **Header Ordering** - Имитация порядка заголовков реальных браузеров
- 🍪 **Cookie Management** - Работа с сессиями и авторизацией на защищенных сайтах
- ⚡ **Worker Pool** - Параллельный парсинг множества страниц с высокой скоростью
- 💾 **Connection Reuse** - Оптимизация для парсинга больших объемов данных
- 🚀 **HTTP/2 & HTTP/1.1** - Выбор протокола в зависимости от сайта

## Установка

```bash
go get github.com/Scryptor/cycletlsR
```

**Требования:**
- Go 1.18+
- Linux/macOS/Windows

## Быстрый старт для парсинга

### Базовый парсинг с обходом защиты

```go
package main

import (
    "fmt"
    "log"
    cycletls "github.com/Scryptor/cycletlsR"
)

func main() {
    client := cycletls.Init()
    
    // JA3 fingerprint от Chrome 120
    chromeJA3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
    
    response, err := client.Do("https://example.com/api/data", cycletls.Options{
        JA3:       chromeJA3,
        UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Headers: map[string]string{
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": `"Windows"`,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
    }, "GET")
    
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Status: %d\nBody: %s\n", response.Status, response.Body)
}
```

### Парсинг с ротацией прокси

```go
// Список прокси для ротации
proxies := []string{
    "http://user1:pass1@proxy1.example.com:8080",
    "socks5://user2:pass2@proxy2.example.com:1080",
    "http://user3:pass3@proxy3.example.com:8080",
}

// Функция для выбора случайного прокси
func getRandomProxy() string {
    return proxies[rand.Intn(len(proxies))]
}

// Парсинг с ротацией
for i := 0; i < 100; i++ {
    response, err := client.Do("https://target-site.com/page", cycletls.Options{
        Proxy: getRandomProxy(),
        JA3: chromeJA3,
        UserAgent: getUserAgent(), // Функция для ротации User-Agent
    }, "GET")
    
    if err != nil {
        log.Printf("Ошибка с прокси %d: %v", i, err)
        continue
    }
    
    // Обработка HTML/JSON
    processData(response.Body)
    
    // Случайная задержка между запросами
    time.Sleep(time.Duration(rand.Intn(3)+1) * time.Second)
}
```

### Массовый парсинг с Worker Pool

```go
client := cycletls.Init(true) // Включаем worker pool

// Список URL для парсинга
urls := []string{
    "https://site.com/page1",
    "https://site.com/page2",
    // ... тысячи URL
}

// Добавляем задачи в очередь
for _, url := range urls {
    client.Queue(url, cycletls.Options{
        JA3: getRandomJA3(), // Ротация JA3
        Proxy: getRandomProxy(),
        Headers: getBrowserHeaders(),
    }, "GET")
}

// Обработка результатов
go func() {
    for response := range client.RespChan {
        if response.Status == 200 {
            saveToDatabase(response.Body)
        } else if response.Status == 403 {
            log.Printf("Блокировка на %s, меняем прокси", response.FinalUrl)
            // Логика обработки блокировок
        }
    }
}()
```

## Стратегии обхода защиты

### Работа с защитами типа WAF/CDN

```go
// Специальные настройки для обхода защиты
response, err := client.Do("https://protected-site.com", cycletls.Options{
    JA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Headers: map[string]string{
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Ch-Ua": `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": `"Windows"`,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    HeaderOrder: []string{
        "host",
        "connection",
        "cache-control",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
    },
}, "GET")
```

### Работа с JavaScript-защитой

```go
// Первый запрос для получения cookies и токенов
response, err := client.Do("https://js-protected.com", cycletls.Options{
    JA3: chromeJA3,
    UserAgent: chromeUA,
}, "GET")

// Сохраняем cookies
cookies := response.Cookies

// Второй запрос с cookies для доступа к защищенному контенту
response, err = client.Do("https://js-protected.com/api/data", cycletls.Options{
    JA3: chromeJA3,
    UserAgent: chromeUA,
    Cookies: convertHTTPCookiesToCycleTLS(cookies),
    Headers: map[string]string{
        "Referer": "https://js-protected.com",
        "X-Requested-With": "XMLHttpRequest",
    },
}, "GET")
```

### Парсинг с авторизацией

```go
// Вход в систему
loginData := url.Values{
    "username": {"user"},
    "password": {"pass"},
}.Encode()

loginResp, err := client.Do("https://site.com/login", cycletls.Options{
    JA3: chromeJA3,
    Headers: map[string]string{
        "Content-Type": "application/x-www-form-urlencoded",
    },
    Body: loginData,
}, "POST")

// Сохраняем сессионные cookies
sessionCookies := loginResp.Cookies

// Парсинг защищенных страниц
response, err := client.Do("https://site.com/protected/data", cycletls.Options{
    JA3: chromeJA3,
    Cookies: convertHTTPCookiesToCycleTLS(sessionCookies),
}, "GET")
```

## Лучшие практики для парсинга

### Ротация fingerprints

```go
// Набор JA3 отпечатков разных браузеров
ja3Fingerprints := map[string]string{
    "chrome120": "771,4865-4866-4867-49195-49199...",
    "firefox121": "771,4865-4867-4866-49195-49199...",
    "safari17": "771,4865-4866-4867-49196-49195...",
}

// Набор User-Agent строк
userAgents := map[string]string{
    "chrome120": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
    "firefox121": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101...",
    "safari17": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15...",
}

// Выбор случайного браузера
browsers := []string{"chrome120", "firefox121", "safari17"}
browser := browsers[rand.Intn(len(browsers))]

response, err := client.Do(url, cycletls.Options{
    JA3: ja3Fingerprints[browser],
    UserAgent: userAgents[browser],
}, "GET")
```

### Управление задержками

```go
// Имитация человеческого поведения
func humanDelay() {
    // Случайная задержка от 2 до 7 секунд
    delay := time.Duration(rand.Intn(5)+2) * time.Second
    time.Sleep(delay)
}

// Парсинг с реалистичными паузами
for _, url := range urls {
    response, err := client.Do(url, options, "GET")
    
    if err != nil {
        // Увеличенная пауза при ошибке
        time.Sleep(30 * time.Second)
        continue
    }
    
    humanDelay()
}
```

### Обработка rate limits

```go
// Адаптивное управление скоростью запросов
var (
    requestCount int
    resetTime    time.Time
    maxRequests  = 100
    timeWindow   = time.Hour
)

func checkRateLimit() bool {
    now := time.Now()
    if now.After(resetTime) {
        requestCount = 0
        resetTime = now.Add(timeWindow)
    }
    
    if requestCount >= maxRequests {
        sleepTime := resetTime.Sub(now)
        log.Printf("Rate limit достигнут, пауза на %v", sleepTime)
        time.Sleep(sleepTime)
        requestCount = 0
    }
    
    requestCount++
    return true
}

// Использование
if checkRateLimit() {
    response, err := client.Do(url, options, "GET")
    // ...
}
```

## API Reference

### Options для парсинга

```go
type Options struct {
    URL                string            // URL для парсинга
    Method             string            // HTTP метод
    Headers            map[string]string // Заголовки браузера
    Body               string            // Тело запроса (для POST)
    Ja3                string            // TLS fingerprint
    UserAgent          string            // User-Agent строка
    Proxy              string            // Прокси сервер
    Cookies            []Cookie          // Cookies для сессии
    Timeout            int               // Таймаут соединения
    DisableRedirect    bool              // Отключить автоматические редиректы
    HeaderOrder        []string          // Порядок заголовков
    InsecureSkipVerify bool              // Пропуск проверки SSL (для отладки)
    ForceHTTP1         bool              // Принудительный HTTP/1.1
}
```

### Response структура

```go
type Response struct {
    RequestID string          // ID запроса
    Status    int             // HTTP статус код
    Body      string          // HTML/JSON контент
    Headers   map[string]string // Заголовки ответа
    Cookies   []*http.Cookie  // Cookies из ответа
    FinalUrl  string          // Финальный URL после редиректов
}
```

## Оптимизация для парсинга

### Настройка производительности

```go
// Оптимальные настройки для парсинга
client := cycletls.Init(true) // Worker pool включен

// Настройка параметров
options := cycletls.Options{
    Timeout: 30,              // Увеличенный таймаут для медленных сайтов
    DisableRedirect: false,   // Следуем редиректам
    ForceHTTP1: false,       // Используем HTTP/2 где возможно
}
```

### Обработка ошибок при парсинге

```go
func parsePage(url string) (string, error) {
    maxRetries := 3
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        response, err := client.Do(url, getOptions(), "GET")
        
        if err == nil && response.Status == 200 {
            return response.Body, nil
        }
        
        lastErr = err
        
        // Анализ ошибки
        if err != nil {
            if strings.Contains(err.Error(), "timeout") {
                log.Printf("Таймаут, повтор %d/%d", i+1, maxRetries)
                time.Sleep(time.Duration(i+1) * 5 * time.Second)
                continue
            }
            
            if strings.Contains(err.Error(), "connection refused") {
                // Меняем прокси при блокировке
                changeProxy()
            }
        }
        
        // Обработка HTTP статусов
        if response != nil {
            switch response.Status {
            case 403, 429:
                log.Printf("Блокировка (код %d), меняем прокси", response.Status)
                changeProxy()
            case 500, 502, 503, 504:
                log.Printf("Ошибка сервера (код %d), повтор через 30 сек", response.Status)
                time.Sleep(30 * time.Second)
            }
        }
        
        time.Sleep(time.Duration(i+1) * 10 * time.Second)
    }
    
    return "", fmt.Errorf("не удалось спарсить %s после %d попыток: %v", url, maxRetries, lastErr)
}
```