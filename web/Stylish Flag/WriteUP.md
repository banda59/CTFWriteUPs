
## Explain
![](web/Stylish%20Flag/image1.png)
> [https://tommytheduck.github.io/stylish_flag/](https://tommytheduck.github.io/stylish_flag/)

싫어요 35개를..받은 문제인데 인상깊어서 가져와봤다.
처음 들어갔는데 이런 UI가 나타나있고 "where is the flag" 라는 문구까지 적혀있는 것을 보니 사이트에 인간의 눈에 안보이게 숨겨져있는 문자가 있을 것 같았다.


```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Stylish Flag</title>
  <link rel="stylesheet" href="csss.css">
  <style>
    body {
      background: #111;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    h1 {
      font-size: 100px;
      color: #0f0;
    }

    .flag {
      width: 8px;
      height: 8px;
      background: #0f0;
      transform: rotate(180deg);
      opacity: 0.05;
      box-shadow:
        264px 0px #0f0,
        1200px 0px #0f0,
        0px 8px #0f0,
        32px 8px #0f0,
        88px 8px #0f0,
        96px 8px #0f0,
...
```

HTML과 CSS를 보면 플래그는 실제로 텍스트 형태로 존재하지 않고, `.flag`라는 숨겨진 `<div>`의 **box-shadow** 속성에 픽셀 단위로 “그려져 있는” 형태라고 한다.

찾아보니 “CSS pixel-art flag” 문제이고, `box-shadow`에 기록된 x,y 좌표를 8px 단위로 찍으면 초록색 점들이 모여서 플래그 문자열이 나타난다고 한다.

```html
<div class="flag"></div>
```
원래 <div hidden class="flag">... 였던 이 hidden 부분을 지우면 초록색 점들이 나타나면서 플래그가 나타난다


![](web/Stylish%20Flag/image2.png)
이후 웹사이트를 확인해보면 이런 플래그 형태로 옅은 녹색 글자가 나타났다.

![](web/Stylish%20Flag/image3.png)
웹사이트 코드를 계속 수정해서 여기까지 발견했는데, 

![](web/Stylish%20Flag/image4.png)
글씨체가 문자가 잘 안보이는 글씨체라서 {H1D30UT_CSS} {H1D3OUT_CSS} {H1D31N_CSS} {H1D3?UT_CSS}도 아무것도 플래그가 아니었다. 특히 3 옆에있는 저 애매한 8같은...O같은... D같은.. 저 글씨체의 문자를 맞추는데 30분이 넘게 걸린 것 같다. 정답은 정확히 기억이 나지 않는데 {H1D30UT_CS5}였던 것 같다. (이것도 확실하지 않다)

사람들이 다들 나와 같은 상황을 겪었는지 👎로 가득했다..