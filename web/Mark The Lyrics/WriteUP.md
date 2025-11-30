
## Explain

![](web/Mark%20The%20Lyrics/image1.png)
> https://tommytheduck.github.io/mckey/

먼저 문제 사이트에 들어가면 노래방이 시작된다.
플래그가 나올까 하여 감미로운 노래를 한번 감상해보는 것으로 시작한다.


![](web/Mark%20The%20Lyrics/image2.png)
풀이는 사실 간단하다.
개발자 도구를 열고 Elements에서 가사가 적혀있는 부분을 살펴보면, 이렇게 `<mark> </mark>`안에 감싸져 있는 문구가 있다. 위의 이미지의 경우에는 -ooh-이다.
이 내용들을 모든 가사들 순서대로 `<mark> </mark>` 부분끼리만 이어붙이면

```js
[...document.querySelectorAll('mark')]
  .map(el => el.textContent)
  .join('');
// 출력: "V1T{MCK-pap-cool-ooh-yeah}"
```
개발자 도구로 플래그를 바로 출력해보기 위해 위와 같은 출력이 나타나는 것을 확인할 수 있다. 즉, 플래그는 아래와 같다.

## Solved

![](pwnable/Feather%20Father/image1.png)
```
    V1T{MCK-pap-cool-ooh-yeah}
```

