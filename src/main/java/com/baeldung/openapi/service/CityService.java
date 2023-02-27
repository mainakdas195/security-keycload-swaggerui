package com.baeldung.openapi.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.baeldung.openapi.entity.City;
import com.baeldung.openapi.repository.CityRepository;



@Service
public class CityService {

	@Autowired
	CityRepository cityRepository;
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CityService.class);
	
	public List<City> getAll(){
		List<City> cityList = new ArrayList<>();
		cityRepository.findAll().forEach(cityList::add);
		LOGGER.debug("Successfully retrieve data from Table city");
		
		return cityList;
	}
}
