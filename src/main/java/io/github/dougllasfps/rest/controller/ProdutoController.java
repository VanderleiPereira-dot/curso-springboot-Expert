package io.github.dougllasfps.rest.controller;

import io.github.dougllasfps.domain.entity.Cliente;
import io.github.dougllasfps.domain.entity.Produto;
import io.github.dougllasfps.domain.repository.Produtos;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.validation.Valid;
import java.util.List;

import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping("/api/produtos")
public class ProdutoController {

    private Produtos repository;

    public ProdutoController(Produtos repository) {
        this.repository = repository;
    }

    @PostMapping
    @ResponseStatus(CREATED)
    @ApiOperation("Salva um novo Produto")
    @ApiResponses({
            @ApiResponse(code = 201, message = "Produto  salvo com sucesso"),
            @ApiResponse(code = 400, message = "Erro de validação")
    })
    public Produto save( @RequestBody @Valid Produto produto ){
        return repository.save(produto);
    }

    @PutMapping("{id}")
    @ResponseStatus(NO_CONTENT)
    @ApiOperation("Atualizar detalhes de um Produto")
    public void update( @PathVariable Integer id,
                        @RequestBody @Valid Produto produto ){
        repository
                .findById(id)
                .map( p -> {
                   produto.setId(p.getId());
                   repository.save(produto);
                   return produto;
                }).orElseThrow( () ->
                new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Produto não encontrado."));
    }

    @DeleteMapping("{id}")
    @ResponseStatus(NO_CONTENT)
    @ApiOperation("Deleta um produto da Base de dados")
    public void delete(@PathVariable Integer id){
        repository
                .findById(id)
                .map( p -> {
                    repository.delete(p);
                    return Void.TYPE;
                }).orElseThrow( () ->
                new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Produto não encontrado."));
    }

    @GetMapping("{id}")
    @ApiOperation("Obter detalhes de um Produto")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Produto encontrado"),
            @ApiResponse(code = 404, message = "Produto não encontrado para o ID informado")
    })
    public Produto getById(@PathVariable Integer id){
        return repository
                .findById(id)
                .orElseThrow( () ->
                new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Produto não encontrado."));
    }

    @GetMapping
    @ApiOperation("Obter detalhes do(s) Produto(s)")
    public List<Produto> find(Produto filtro ){
        ExampleMatcher matcher = ExampleMatcher
                .matching()
                .withIgnoreCase()
                .withStringMatcher(
                        ExampleMatcher.StringMatcher.CONTAINING );

        Example example = Example.of(filtro, matcher);
        return repository.findAll(example);
    }
}