---
layout: post
title: 【note】GitPrey使用笔记
date: 2019-5-19
categories: blog
tags: 
description: 
---

## 简介
github是一个大大大宝藏，里面藏着许许多多的好东西。用心翻找的话，会有无数意外的惊喜。而GitPrey就是一把好用的铲子，不过原始链接的GitPrey直接运行，是没有结果输出的。

本文记录了调试后的问题点，作为笔记备忘。

GitPrey地址如下:
`https://github.com/repoog/GitPrey`

## 问题点&修改方式
其实GitPray工程就一个py文件，内容相对简单。

通过对代码逻辑的梳理，发现运行无输出的问题点在于`__file_name_inspect`函数，该函数未能取到任何的repo名，导致后续无任何输出。

关键代码如下：

`repo_list = project_html.select('div .d-inline-block.col-10 > a:nth-of-type(2)')`

不晓得是否github做了更新，目前github对于搜索结果的页面元素中已经没有采用`d-inline-block`了，而是`<div class="flex-auto min-width-0 col-10">`。

因此需要将关键代码稍作调整，修改为：

`repo_list = project_html.select('div .flex-auto.col-10 > a:nth-of-type(2)')`

大功告成。