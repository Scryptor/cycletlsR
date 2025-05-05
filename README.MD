# CycleTLSR

Продвинутый HTTP-клиент на Go с возможностью эмуляции TLS-отпечатков браузеров для обхода защит.

> **Примечание:** Это форк репозитория, с некоторыми улучшениями [Danny-dasilva/cycletls](https://github.com/Danny-dasilva/cycletls)

## 🚀 Возможности

- **Высокая производительность** - Встроенный пул горутин для асинхронной обработки запросов
- **Настраиваемый порядок заголовков** с использованием [fhttp](https://github.com/useflyent/fhttp)
- **Поддержка прокси** - HTTP(S), Socks4, Socks5, Socks5h
- **Настройка JA3-отпечатков** для имитации различных браузеров

## Содержание

* [Установка](#установка)
* [Использование](#использование)
* [Инициализация CycleTLS](#создание-экземпляра)
* [API и методы](#методы-cycletls)
* [Конфигурация запросов](#конфигурация-запросов-cycletls)
* [Схема ответа](#схема-ответа-cycletls)
* [Пример множественных запросов](#пример-множественных-запросов)

## Зависимости

```
Go версии 1.21+
```

## Установка

```bash
$ go get github.com/Scryptor/cycletlsR
```

## Использование

### Пример базового запроса

```go
package main

import (
	"log"
	"github.com/Scryptor/cycletlsR"
)

func main() {
	client := cycletlsR.Init()

	response, err := client.Do("https://chek.ja3.org", cycletlsR.Options{
		Body : "",
		Ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
		UserAgent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
	}, "GET")
	
	if err != nil {
		log.Print("Ошибка запроса: " + err.Error())
	}
	
	log.Println(response)
}
```

### Пример использования собственного http.Client

```go
import (
	"github.com/Scryptor/cycletlsR"
	http "github.com/Scryptor/fhttp" // обратите внимание, что это замена для net/http
)

func main() {
	ja3 := "771,52393-52392-52244-52243-49195-49199-49196-49200-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0"
	ua := "Chrome Version 57.0.2987.110 (64-bit) Linux"

	cycleClient := &http.Client{
		Transport: cycletlsR.NewTransport(ja3, ua),
	}

	resp, err := cycleClient.Get("https://tls.peet.ws/")
	// ...
}
```

## Создание экземпляра

```go
import (
	"github.com/Scryptor/cycletlsR"
)

// Функция Init() инициализирует каналы Go для обработки запросов
client := cycletlsR.Init()
```

## Методы CycleTLS

Доступны следующие методы:

- **client.Do(url, options, method)** - Выполнение запроса с указанным методом
- **Init(workers ...bool)** - Инициализация клиента (с опциональным пулом воркеров)
- **Queue(url, options, method)** - Добавление запроса в очередь
- **Close()** - Закрытие клиента и освобождение ресурсов

## Конфигурация запросов CycleTLS

```go
type Options struct {
    URL                string            // URL для запроса
    Method             string            // Метод запроса (GET, POST, и т.д.)
    Headers            map[string]string // Пользовательские заголовки
    Body               string            // Тело запроса
    Ja3                string            // JA3-отпечаток
    UserAgent          string            // User-Agent
    Proxy              string            // Прокси (формат: http://username:password@hostname:port)
    Cookies            []Cookie          // Cookies для запроса
    Timeout            int               // Таймаут в секундах (по умолчанию: 7)
    DisableRedirect    bool              // Отключение перенаправлений
    HeaderOrder        []string          // Порядок заголовков
    OrderAsProvided    bool              // Использовать порядок заголовков как предоставлено
    InsecureSkipVerify bool              // Пропуск проверки сертификата (небезопасно)
    ForceHTTP1         bool              // Принудительное использование HTTP/1
}
```

### Пример с Cookies

```go
type Cookie struct {
    Name       string
    Value      string
    Path       string     // опционально
    Domain     string     // опционально
    Expires    time.Time  // опционально
    RawExpires string     // для чтения cookies
    MaxAge     int        // опционально
    Secure     bool       // опционально
    HTTPOnly   bool       // опционально
    SameSite   http.SameSite // опционально
}
```

## Схема ответа CycleTLS

```go
type Response struct {
    RequestID string             // ID запроса
    Status    int                // Код статуса ответа
    Body      string             // Тело ответа
    Headers   map[string]string  // Заголовки ответа
    Cookies   []*http.Cookie     // Cookies из ответа
    FinalUrl  string             // Финальный URL (полезно при перенаправлениях)
}
```

## Пример множественных запросов

В Go можно использовать встроенный worker pool для длительных асинхронных запросов:

```go
package main

import (
	"log"
	cycletls "github.com/Scryptor/cycletlsR"
)

// Статические переменные
var (
	ja3       = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
	userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36"
)

// RequestConfig содержит конфигурацию для каждого запроса
type RequestConfig struct {
	URL     string
	Method  string
	Options cycletls.Options
}

func main() {
	client := cycletls.Init(true) // Инициализация с пулом воркеров

	// Определение запросов
	requests := []RequestConfig{
		{
			URL:    "http://httpbin.org/delay/4",
			Method: "GET",
			Options: cycletls.Options{
				Ja3:       ja3,
				UserAgent: userAgent,
			},
		},
		{
			URL:    "http://httpbin.org/post",
			Method: "POST",
			Options: cycletls.Options{
				Body:      `{"field":"POST-VAL"}`,
				Ja3:       ja3,
				UserAgent: userAgent,
			},
		},
		{
			URL:    "https://chek.ja3.org",
			Method: "GET",
			Options: cycletls.Options{
				Ja3:       ja3,
				UserAgent: userAgent,
				Cookies: []cycletls.Cookie{
					{
						Name:  "example1",
						Value: "aaaaaaa",
					},
				},
			},
		},
	}

	// Добавление запросов в очередь
	for _, req := range requests {
		client.Queue(req.URL, req.Options, req.Method)
	}

	// Асинхронное чтение ответов по мере их получения
	// Они будут возвращаться по мере обработки
	// Например, запрос с Delay 3 будет возвращен последним
	for i := 0; i < len(requests); i++ {
		response := <-client.RespChan
		log.Println("Ответ:", response)
	}

	// Закрытие клиента
	client.Close()
}
```

## Работа со стандартным cookiejar

```go
package main

import (
	"github.com/Scryptor/cycletlsR"
	"log"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

func main() {
	client := cycletlsR.Init()
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	
	// Первый запрос для установки cookies
	firstResponse, err := client.Do("https://httpbin.org/cookies/set?a=1&b=2&c=3", cycletlsR.Options{
		Body: "",
		Ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
		DisableRedirect: true,
	}, "GET")
	
	if err != nil {
		log.Fatal(err)
	}
	
	firstURL, _ := url.Parse(firstResponse.FinalUrl)
	jar.SetCookies(firstURL, firstResponse.Cookies)

	// Второй запрос с cookie из первого ответа
	secondResponse, err := client.Do("https://httpbin.org/cookies", cycletlsR.Options{
		Body: "",
		Ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
		Headers: map[string]string{
			"Cookie": getHeadersFromJar(jar, firstURL),
		},
	}, "GET")
	
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Ответ второго запроса:", secondResponse.Body)
}

// Преобразование cookies из jar в строку заголовка
func getHeadersFromJar(jar *cookiejar.Jar, url *url.URL) string {
	cookies := jar.Cookies(url)
	var cookieStrs []string
	for _, cookie := range cookies {
		cookieStrs = append(cookieStrs, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(cookieStrs, "; ")
}
```

## Отправка multipart/form-data

### Текстовые данные формы

```go
package main

import (
	"bytes"
	"github.com/Scryptor/cycletlsR"
	"log"
	"mime/multipart"
)

func main() {
	client := cycletlsR.Init()

	// Подготовка буфера для создания multipart формы
	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)

	// Добавление полей формы
	multipartWriter.WriteField("key1", "value1")
	multipartWriter.WriteField("key2", "value2")

	contentType := multipartWriter.FormDataContentType()
	// Закрытие writer перед отправкой запроса
	multipartWriter.Close()

	response, err := client.Do("http://httpbin.org/post", cycletlsR.Options{
		Body: requestBody.String(),
		Headers: map[string]string{
			"Content-Type": contentType,
		},
	}, "POST")

	if err != nil {
		log.Print("Ошибка запроса: " + err.Error())
	}

	log.Println(response.Body)
}
```

### Загрузка файлов через form-data

```go
package main

import (
	"github.com/Scryptor/cycletlsR"
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"os"
)

func main() {
	client := cycletlsR.Init()

	// Подготовка буфера для создания multipart формы
	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)

	// Добавление файла
	fileWriter, err := multipartWriter.CreateFormFile("fieldname", "filename")
	if err != nil {
		log.Fatal("Ошибка CreateFormFile: ", err)
	}

	// Открытие файла для загрузки
	file, err := os.Open("путь/к/файлу")
	if err != nil {
		log.Fatal("Ошибка открытия файла: ", err)
	}
	defer file.Close()

	// Копирование файла в multipart writer
	_, err = io.Copy(fileWriter, file)
	if err != nil {
		log.Fatal("Ошибка копирования файла: ", err)
	}

	// Закрытие writer перед отправкой запроса
	contentType := multipartWriter.FormDataContentType()
	multipartWriter.Close()

	response, err := client.Do("http://httpbin.org/post", cycletlsR.Options{
		Body: requestBody.String(),
		Headers: map[string]string{
			"Content-Type": contentType,
		},
	}, "POST")

	if err != nil {
		log.Print("Ошибка запроса: " + err.Error())
	}

	log.Println(response.Body)
}
```

## Отправка application/x-www-form-urlencoded

```go
package main

import (
	"log"
	"net/url"
	"github.com/Scryptor/cycletlsR"
)

func main() {
	client := cycletlsR.Init()

	// Подготовка данных формы
	form := url.Values{}
	form.Add("key1", "value1")
	form.Add("key2", "value2")

	response, err := client.Do("http://httpbin.org/post", cycletlsR.Options{
		Body: form.Encode(),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}, "POST")
	
	if err != nil {
		log.Print("Ошибка запроса: " + err.Error())
	}
	
	log.Println(response.Body)
}
```

## Загрузка изображений

Изображения с заголовком `Content-Type` следующих типов автоматически кодируются в base64:

**Поддерживаемые типы изображений**
* `image/svg+xml`
* `image/webp`
* `image/jpeg`
* `image/png`
* `application/pdf`

```go
package main

import (
	"encoding/base64"
	"os"
	"github.com/Scryptor/cycletlsR"
)

func main() {
	client := cycletlsR.Init()
	
	response, err := client.Do("http://httpbin.org/image/jpeg", cycletlsR.Options{
		Body:      "",
		Ja3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36",
	}, "GET")
	
	// Декодирование Base64
	dec, err := base64.StdEncoding.DecodeString(response.Body)
	if err != nil {
		panic(err)
	}
	
	// Создание файла
	f, err := os.Create("test.jpeg")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	
	// Запись декодированных данных в файл
	if _, err := f.Write(dec); err != nil {
		panic(err)
	}
	
	if err := f.Sync(); err != nil {
		panic(err)
	}
}
```

## Принудительное использование HTTP/1

```go
package main

import (
	"github.com/Scryptor/cycletlsR"
	"log"
)

func main() {
	client := cycletlsR.Init()
	
	response, err := client.Do("https://chek.ja3.org", cycletlsR.Options{
		ForceHTTP1: true,
	}, "GET")
	
	if err != nil {
		log.Print("Ошибка запроса: " + err.Error())
	}
	
	log.Println(response.Body) // Вы можете проверить HTTP_Version в ответе
}
```