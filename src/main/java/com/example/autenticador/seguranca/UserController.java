package com.example.autenticador.seguranca;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class UserController {

	@GetMapping(value = "/login")
	public ModelAndView login() {
		return new ModelAndView("/visao/login");
	}

	@GetMapping(value = "/")
	public ModelAndView index() {
		return new ModelAndView("/visao/index");
	}

	@GetMapping(value = "/i")
	public ModelAndView index1() {
		return new ModelAndView("/visao/index1");
	}

}
