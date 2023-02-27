package com.baeldung.openapi.delegateimpl;

import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.baeldung.openapi.constant.Paths;
import com.baeldung.openapi.model.CityDto;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringRunner.class)
@SpringBootTest
public class CitiesApiDelegateImplTest {
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    @Rule
    public JUnitRestDocumentation restDocumentation = new JUnitRestDocumentation();
    @Autowired
    private WebApplicationContext context;
    private MockMvc mockMvc;

    @Before
    public void beforeEach() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
                .apply(documentationConfiguration(this.restDocumentation))
                .build();
    }

    @Test
    public void getAllCities_Test() throws Exception {
    	
    	MvcResult receivedUser = this.mockMvc.perform(MockMvcRequestBuilders
                .get(Paths.ALL_CITIES_PATH)
                .contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

    	List<CityDto> citiesDto = OBJECT_MAPPER.readValue(receivedUser.getResponse().getContentAsString(), new TypeReference<List<CityDto>>(){});
    	System.out.print(citiesDto);
    	

    }
}
