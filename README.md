# lkm-rootkit
A simple lkm rootkit for fun and profit.

## Description
This is a linux kernel module rootkit which turns any command line parameter

begining with "http://", "https://" and "www." into "www.bilibil.com".

For example, if you type "curl www.baidu.com" in your terminal, this modules

will know that you actually mean "curl www.bilibili.com", and will help you

do the translating, automatically.

## Usage
issue the following command to see the effect.
`
 $make
 
 $sudo insmod lkm-rootkit.ko
 
 $curl www.baidu.com
 
 $sudo rmmod lkm_rootkit
 
 $curl www.baidu.com
`
 
 
 