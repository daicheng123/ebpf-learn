package main

import (
	"fmt"
	"os"
	"time"
)

func writeFile() {
	f, err := os.OpenFile("test.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.WriteString(time.Now().String())
}

// TODO 本课程来自 程序员在囧途(www.jtthink.com) 咨询群：98514334
func main() {
	fmt.Println("当前的PID是：", os.Getpid())
	for {
		writeFile()
		fmt.Println("写入成功", time.Now())
		time.Sleep(time.Second * 5)
	}
}
