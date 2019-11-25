package mpsquic

import (
	"errors"
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
)

// Parse raw forwarding path spath.Path to combinator.Path
func parseSPath(vpath spath.Path) (cpath *combinator.Path, err error) {
	var segments []*combinator.Segment
	var interfaces []sciond.PathInterface

	vpath.InfOff = 0
	vpath.HopOff = common.LineLen // skip InfoField, cannot use vpath.InitOffsets() as it skips more

	infoF, err := vpath.GetInfoField(vpath.InfOff)
	if err != nil {
		return nil, err
	}
	for {
		if vpath.HopOff >= len(vpath.Raw) {
			break
		}
		var segment *combinator.Segment

		if vpath.HopOff-vpath.InfOff > int(infoF.Hops)*spath.HopFieldLength {
			// Switch to next segment
			vpath.InfOff = vpath.HopOff
			infoF, err = vpath.GetInfoField(vpath.InfOff)
			if err != nil {
				return nil, err
			}
			vpath.HopOff += common.LineLen
		}

		var hopFields []*combinator.HopField
		var segInterfaces []sciond.PathInterface
		for i := 0; i < int(infoF.Hops); i++ {
			hf, err := vpath.GetHopField(vpath.HopOff)
			if err != nil {
				return nil, err
			}
			vpath.HopOff += spath.HopFieldLength

			hopFields = append(hopFields, &combinator.HopField{hf})
			segInterfaces = append(segInterfaces, sciond.PathInterface{0, hf.ConsIngress})
			segInterfaces = append(segInterfaces, sciond.PathInterface{0, hf.ConsEgress})
		}

		segment = &combinator.Segment{
			InfoField:  &combinator.InfoField{infoF},
			HopFields:  hopFields,
			Type:       0,
			Interfaces: segInterfaces,
		}
		segments = append(segments, segment)
		interfaces = append(interfaces, segInterfaces...)
	}
	if !vpath.IsEmpty() && len(segments) == 0 {
		return nil, errors.New(fmt.Sprintf("Invalid raw path length. HopOff=%v, len(Raw)=%v", vpath.HopOff, len(vpath.Raw)))
	}
	return &combinator.Path{
		Segments:   segments,
		Weight:     0,
		Mtu:        0,
		Interfaces: interfaces,
	}, nil
}

// Debug helpers

func printHFDetails(path *spath.Path) {
	cpath, err := parseSPath(*path)
	if err != nil {
		fmt.Printf("\n\nERROR: Failed to parse path info. err:%v", err)
		return
	}
	fmt.Printf("\nFields:")
	for _, s := range cpath.Segments {
		for _, hf := range s.HopFields {
			XoverVal := "."
			if hf.Xover {
				XoverVal = "X"
			}
			VerifyOnlyVal := "."
			if hf.VerifyOnly {
				VerifyOnlyVal = "V"
			}
			fmt.Printf("\n\tHF %s%s InIF: %3v OutIF: %3v \t\t\tExpTime: %v Mac: %v",
				XoverVal, VerifyOnlyVal, hf.ConsIngress, hf.ConsEgress, hf.ExpTime, hf.Mac)
		}
	}
	fmt.Println()
}
