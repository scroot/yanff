package common_test

import (
	"github.com/intel-go/yanff/common"
	"reflect"
	"testing"
)

const (
	BigCPUNum   = 40
	SmallCPUNum = 3
)

var cpuParseTests = []struct {
	line     string // input
	cpuNum   uint   // max number of cpus
	expected []uint // expected result
}{

	{"", BigCPUNum, []uint{}},
	{"18-21", BigCPUNum, []uint{18, 19, 20, 21}},
	{"11,12,45", BigCPUNum, []uint{11, 12, 45}},
	{"1,20-24,9", BigCPUNum, []uint{1, 20, 21, 22, 23, 24, 9}},
	{"10-14,13-15", BigCPUNum, []uint{10, 11, 12, 13, 14, 15}},
	{"10-14,11-12", BigCPUNum, []uint{10, 11, 12, 13, 14}},
	{"10-14,11-12", BigCPUNum, []uint{10, 11, 12, 13, 14}},
	{"", SmallCPUNum, []uint{}},
	{"18-21", SmallCPUNum, []uint{18, 19, 20}},
	{"11,12,45", SmallCPUNum, []uint{11, 12, 45}},
	{"1,20-24,9", SmallCPUNum, []uint{1, 20, 21}},
	{"10-14,13-15", SmallCPUNum, []uint{10, 11, 12}},
	{"10-14,11-12", SmallCPUNum, []uint{10, 11, 12}},
	{"10-14,11-12", SmallCPUNum, []uint{10, 11, 12}},
}

func TestParseCPUList(t *testing.T) {
	for _, tt := range cpuParseTests {
		actual := common.ParseCPUs(tt.line, tt.cpuNum)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("ParseCPUs(%s): expected %v, actual %v", tt.line, tt.expected, actual)
		}
	}
}
