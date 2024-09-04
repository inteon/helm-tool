package random

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/cert-manager/helm-tool/linter/parsetemplates/funcs_serdes"
	"github.com/cert-manager/helm-tool/linter/sets"
	"github.com/cert-manager/helm-tool/parser"
	"gopkg.in/yaml.v3"
)

func FuzzTest(f *testing.F) {
	templatesFolder := "testdata/templates"
	valuesFile := "testdata/values.yaml"

	document, err := parser.Load(valuesFile, true)
	if err != nil {
		f.Fatalf("Failed to load values file: %v", err)
	}

	templates, err := setupTemplates(templatesFolder)
	if err != nil {
		f.Fatalf("Failed to setup templates: %v", err)
	}

	defaultYaml, err := os.ReadFile(valuesFile)
	if err != nil {
		f.Fatalf("Failed to read values file: %v", err)
	}

	defaultValues := map[string]interface{}{}
	if err := yaml.Unmarshal(defaultYaml, &defaultValues); err != nil {
		f.Fatalf("Failed to unmarshal values file: %v", err)
	}

	values, err := Renderer(document)
	if err != nil {
		f.Fatalf("Failed to render values: %v", err)
	}

	f.Add([]byte("input"))

	f.Fuzz(func(t *testing.T, randData []byte) {
		vals := values(randData)
		vals = mergeMaps(defaultValues, vals.(map[string]interface{}))

		for template := range templates {
			var yamlOutput bytes.Buffer
			err := template.Execute(&yamlOutput, map[string]interface{}{
				"Chart": map[string]interface{}{
					"Name": "test-chart",
				},
				"Release": map[string]interface{}{
					"Name": "test-release",
				},
				"Values": vals,
			})
			if err != nil && !errors.Is(err, funcs_serdes.ErrFail) {
				yaml, _ := yaml.Marshal(vals)
				t.Logf("Values:\n%s", yaml)

				t.Fatalf("Failed to execute template: %v", err)
			}

			dec := yaml.NewDecoder(bytes.NewReader(yamlOutput.Bytes()))
			var result map[string]any
			for {
				err := dec.Decode(&result)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Logf("YAML:\n%s", yamlOutput.String())

					t.Fatalf("Failed to execute template: %v", err)
				}
			}
		}
	})
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

func setupTemplates(templatesPath string) (sets.Set[*template.Template], error) {
	tmpl := template.New("ROOT")

	tmpl.Funcs(funcs_serdes.FuncMap())

	templates := sets.Set[*template.Template]{}

	// parse all templates
	err := filepath.Walk(
		templatesPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			ext := filepath.Ext(path)
			if ext != ".yaml" &&
				ext != ".yml" &&
				ext != ".tmpl" &&
				ext != ".tpl" {
				return nil
			}

			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			t, err := tmpl.New(path).Parse(string(contents))
			if err != nil {
				return err
			}
			templates[t] = struct{}{}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return templates, nil
}
