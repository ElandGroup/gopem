package smt

import "fmt"

const (
	Black = uint8(iota + 30)
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

var (
	Debug   = CustomerColor{Cyan}   //青色
	Warning = CustomerColor{Yellow} //黄色
	Error   = CustomerColor{Red}    //红色
	Succ    = CustomerColor{Green}
)

type CustomerColor struct {
	ColorNo uint8
}

func (c CustomerColor) Printf(format string, a ...interface{}) {
	s := fmt.Sprintf(format, a...)
	c.doPrint(s)
}
func (c CustomerColor) Println(a ...interface{}) {
	s := fmt.Sprint(a...)
	c.doPrint(s)
}
func (c CustomerColor) doPrint(a interface{}) {

	fmt.Printf("\033[%dm%v\033[0m", c.ColorNo, a)
}
