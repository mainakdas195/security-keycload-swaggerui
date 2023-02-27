package com.baeldung.openapi.repository;

import org.springframework.data.repository.CrudRepository;

import com.baeldung.openapi.entity.City;

public interface CityRepository extends CrudRepository<City, Integer>{

}
