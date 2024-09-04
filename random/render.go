/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package random

import (
	"fmt"

	"github.com/cert-manager/helm-tool/heuristics"
	"github.com/cert-manager/helm-tool/parser"
	"github.com/cert-manager/helm-tool/paths"
	"github.com/cert-manager/helm-tool/random/fuzz"
)

type treeLevel struct {
	Path     paths.Path
	Property *parser.Property
	Children []treeLevel
}

func (t *treeLevel) Type() parser.Type {
	if len(t.Children) == 0 && t.Property != nil {
		return t.Property.Type
	}

	if len(t.Children) > 0 {
		firstChild := t.Children[0]
		if paths.IsArrayPathComponent(firstChild.Path.Property()) {
			return parser.TypeArray
		}

		return parser.TypeObject
	}

	return parser.TypeUnknown
}

func (t *treeLevel) add(path paths.Path, property parser.Property) error {
	if path.Equal(t.Path) {
		t.Property = &property
		return nil
	}

	if !t.Path.IsSubPathOf(path) {
		return fmt.Errorf("path %q is not a subpath of %q", t.Path, path)
	}

	for i, child := range t.Children {
		if child.Path.IsSubPathOf(path) {
			child.add(path, property)
			t.Children[i] = child
			return nil
		}
	}

	t.Children = append(t.Children, treeLevel{Path: t.Path.Expand(path, 1)})
	t.Children[len(t.Children)-1].add(path, property)
	return nil
}

func buildTree(document *parser.Document) (treeLevel, error) {
	allProperties := []parser.Property{}
	for _, section := range document.Sections {
		allProperties = append(allProperties, section.Properties...)
	}

	root := treeLevel{}
	for _, property := range allProperties {
		if err := root.add(property.Path, property); err != nil {
			return treeLevel{}, err
		}
	}

	// Add a global section to the root, as this is a special case.
	// TODO: also handle the case where there is a global section in the
	// values.yaml file.
	root.add(paths.Path{}.WithProperty("global"), parser.Property{
		Type: parser.TypeUnknown,
		Description: parser.Comment{
			CommentBlock: heuristics.CommentBlock{
				Segments: []heuristics.CommentBlockSegment{
					{
						Type:     heuristics.ContentTypeText,
						Contents: []string{"Global values shared across all (sub)charts"},
					},
				},
			},
		},
	})

	return root, nil
}

func (t *treeLevel) randomSample(bs *fuzz.ByteSource) any {
	yamlPrimitive := func(bs *fuzz.ByteSource) any {
		switch bs.IntN(6) {
		case 0:
			return bs.String()
		case 1:
			return bs.Bool()
		case 2:
			return bs.Int64()
		case 3:
			return bs.Float64()
		case 4:
			return bs.Uint64()
		case 5:
			return nil
		}
		panic("unreachable")
	}

	switch t.Type() {
	case parser.TypeString:
		return bs.String()
	case parser.TypeNumber:
		switch bs.IntN(2) {
		case 0:
			return bs.Int64()
		case 1:
			return bs.Float64()
		}
		panic("unreachable")
	case parser.TypeBool:
		return bs.Bool()
	case parser.TypeArray:
		arr := []any{}
		for i := 0; i < bs.IntN(5); i++ {
			arr = append(arr, bs.String())
		}
		return arr
	case parser.TypeObject:
		obj := map[string]any{}
		if len(t.Children) > 0 {
			for _, child := range t.Children {
				if bs.Bool() {
					continue
				}

				obj[paths.SegmentString(child.Path.Property())] = child.randomSample(bs)
			}
		} else {
			for i := 0; i < bs.IntN(5); i++ {
				obj[bs.String()] = yamlPrimitive(bs)
			}
		}
		return obj
	case parser.TypeTimestamp:
		return "2024-01-01T00:00:00Z"
	case parser.TypeUnknown:
		return yamlPrimitive(bs)
	default:
		return nil
	}
}

func Renderer(document *parser.Document) (func(randomData []byte) any, error) {
	tree, err := buildTree(document)
	if err != nil {
		return nil, err
	}

	return func(randomData []byte) any {
		bs := fuzz.NewByteSource(randomData)
		return tree.randomSample(bs)
	}, nil
}
