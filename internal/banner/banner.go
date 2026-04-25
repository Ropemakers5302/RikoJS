package banner

import (
	"fmt"

	"github.com/rikojs/pkg/utils"
)

const Banner = `
   ___  _ __           ______
  / _ \(_) /_____  __ / / __/
 / , _/ /  '_/ _ \/ // /\ \  
/_/|_/_/_/\_\\___/\___/___/ 
    [ JS 攻击面分析工具 ]
        by 彩叶Saya
`

func PrintBanner() {
	cyan := "\033[36m"
	reset := "\033[0m"
	fmt.Printf("%s%s%s\n", cyan, Banner, reset)
	utils.PrintInfo("正在初始化 RikoJS...")
	utils.PrintInfo("一款用于快速分析js文件、路径扫描和ai分析的单兵工具")
	fmt.Println()
}
