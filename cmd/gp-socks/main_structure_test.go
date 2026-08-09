package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestMain_runsCleanupBeforeProcessExit(t *testing.T) {
	// Given
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile(main.go) error = %v", err)
	}
	mainBody := findFunctionBody(t, file, "main")
	runStatement := -1
	stopStatement := -1
	exitStatement := -1

	// When
	for index, statement := range mainBody.List {
		if deferred, ok := statement.(*ast.DeferStmt); ok && isCallTo(deferred.Call, "", "stop") {
			t.Error("main defers stop(), but os.Exit skips deferred cleanup")
		}
		ast.Inspect(statement, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch {
			case isCallTo(call, "", "run"):
				runStatement = index
			case isCallTo(call, "", "stop"):
				if _, direct := statement.(*ast.ExprStmt); direct {
					stopStatement = index
				}
			case isCallTo(call, "os", "Exit"):
				exitStatement = index
			}
			return true
		})
	}

	// Then
	if runStatement < 0 {
		t.Fatal("main does not call run(ctx, args, IO)")
	}
	if stopStatement < 0 {
		t.Fatal("main does not call stop() directly before process exit")
	}
	if exitStatement < 0 {
		t.Fatal("main does not call os.Exit")
	}
	if !(runStatement < stopStatement && stopStatement < exitStatement) {
		t.Fatalf("main statement order run=%d stop=%d os.Exit=%d, want run < stop < os.Exit", runStatement, stopStatement, exitStatement)
	}
}

func TestMain_injectsProcessEnvironmentAndLogWriter(t *testing.T) {
	// Given
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("ParseFile(main.go) error = %v", err)
	}
	mainBody := findFunctionBody(t, file, "main")
	foundEnvironment := false
	foundLogWriter := false
	foundAutoConfig := false

	// When
	ast.Inspect(mainBody, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok || !isSelector(literal.Type, "app", "IO") {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if key.Name == "LookupEnv" && isSelector(field.Value, "os", "LookupEnv") {
				foundEnvironment = true
			}
			if key.Name == "LogWriter" && isSelector(field.Value, "os", "Stderr") {
				foundLogWriter = true
			}
			if key.Name == "AutoConfig" {
				value, ok := field.Value.(*ast.Ident)
				foundAutoConfig = ok && value.Name == "true"
			}
		}
		return true
	})

	// Then
	if !foundEnvironment {
		t.Error("main does not inject os.LookupEnv")
	}
	if !foundLogWriter {
		t.Error("main does not inject os.Stderr as LogWriter")
	}
	if !foundAutoConfig {
		t.Error("main does not enable automatic config.yaml discovery")
	}
}

func findFunctionBody(t *testing.T, file *ast.File, name string) *ast.BlockStmt {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name && function.Body != nil {
			return function.Body
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func isCallTo(call *ast.CallExpr, packageName, functionName string) bool {
	if packageName == "" {
		identifier, ok := call.Fun.(*ast.Ident)
		return ok && identifier.Name == functionName
	}
	return isSelector(call.Fun, packageName, functionName)
}

func isSelector(expression ast.Expr, packageName, name string) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == packageName
}
