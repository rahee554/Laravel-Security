<?php

namespace ArtflowStudio\Scanner\Analyzers;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor;
use PhpParser\Parser;
use PhpParser\ParserFactory;

class CodeAnalyzer
{
    protected Parser $parser;

    public function __construct()
    {
        $this->parser = (new ParserFactory)->createForNewestSupportedVersion();
    }

    /**
     * Parse PHP file and return AST
     */
    public function parseFile(string $filePath): ?array
    {
        try {
            $code = file_get_contents($filePath);

            return $this->parser->parse($code);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Parse PHP code string and return AST
     */
    public function parseCode(string $code): ?array
    {
        try {
            return $this->parser->parse($code);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Find function calls in AST
     */
    public function findFunctionCalls(array $ast, array $functionNames): array
    {
        $results = [];

        $visitor = new class($functionNames, $results) implements NodeVisitor
        {
            public function __construct(private array $functionNames, private array &$results) {}

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Expr\FuncCall) {
                    if ($node->name instanceof Node\Name) {
                        $name = $node->name->toString();
                        if (in_array($name, $this->functionNames)) {
                            $this->results[] = [
                                'function' => $name,
                                'line' => $node->getStartLine(),
                                'args' => count($node->args),
                            ];
                        }
                    }
                }
            }

            public function leaveNode(Node $node) {}

            public function beforeTraverse(array $nodes) {}

            public function afterTraverse(array $nodes) {}
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $results;
    }

    /**
     * Find method calls in AST
     */
    public function findMethodCalls(array $ast, array $methodNames): array
    {
        $results = [];

        $visitor = new class($methodNames, $results) implements NodeVisitor
        {
            public function __construct(private array $methodNames, private array &$results) {}

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
                    if ($node->name instanceof Node\Identifier) {
                        $name = $node->name->toString();
                        if (in_array($name, $this->methodNames)) {
                            $this->results[] = [
                                'method' => $name,
                                'line' => $node->getStartLine(),
                            ];
                        }
                    }
                }
            }

            public function leaveNode(Node $node) {}

            public function beforeTraverse(array $nodes) {}

            public function afterTraverse(array $nodes) {}
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $results;
    }

    /**
     * Find public properties in class
     */
    public function findPublicProperties(array $ast): array
    {
        $results = [];

        $visitor = new class($results) implements NodeVisitor
        {
            public function __construct(private array &$results) {}

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Stmt\Property) {
                    if ($node->isPublic()) {
                        foreach ($node->props as $prop) {
                            $this->results[] = [
                                'name' => $prop->name->toString(),
                                'line' => $node->getStartLine(),
                            ];
                        }
                    }
                }
            }

            public function leaveNode(Node $node) {}

            public function beforeTraverse(array $nodes) {}

            public function afterTraverse(array $nodes) {}
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $results;
    }

    /**
     * Find class methods
     */
    public function findMethods(array $ast): array
    {
        $results = [];

        $visitor = new class($results) implements NodeVisitor
        {
            public function __construct(private array &$results) {}

            public function enterNode(Node $node)
            {
                if ($node instanceof Node\Stmt\ClassMethod) {
                    $this->results[] = [
                        'name' => $node->name->toString(),
                        'line' => $node->getStartLine(),
                        'public' => $node->isPublic(),
                        'protected' => $node->isProtected(),
                        'private' => $node->isPrivate(),
                    ];
                }
            }

            public function leaveNode(Node $node) {}

            public function beforeTraverse(array $nodes) {}

            public function afterTraverse(array $nodes) {}
        };

        $traverser = new NodeTraverser;
        $traverser->addVisitor($visitor);
        $traverser->traverse($ast);

        return $results;
    }

    /**
     * Check if class extends another class
     */
    public function extendsClass(array $ast, string $className): bool
    {
        foreach ($ast as $node) {
            if ($node instanceof Node\Stmt\Class_) {
                if ($node->extends && $node->extends->toString() === $className) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get class name from AST
     */
    public function getClassName(array $ast): ?string
    {
        foreach ($ast as $node) {
            if ($node instanceof Node\Stmt\Class_) {
                return $node->name ? $node->name->toString() : null;
            }
        }

        return null;
    }
}
